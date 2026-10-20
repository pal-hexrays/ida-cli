"""Translate LOAD OPTIONS (and --set/--plugin-opt/--log) into a LoadSpec."""

from __future__ import annotations

import re
from typing import Any

from ..errors import usage
from ..lang.values import parse_int
from .session import LoadSpec
from .settings import Settings

# Loader module names (idx(1)) -> IDA file-format name prefixes accepted by -T.
LOADERS = {
    "pe": "Portable executable", "elf": "ELF", "macho": "Mach-O", "coff": "COFF", "dex": "Android DEX",
    "dsc": "Apple DYLD cache", "uefi_fv": "UEFI firmware", "wasm": "WebAssembly", "windmp": "Windows Crash Dump",
    "omf": "OMF", "ne": "New executable", "lx": "Linear executable", "xbe": "XBOX executable",
    "hexagon_mbn": "Qualcomm MBN", "ihex": "Intel Hex", "ar": "Archive", "binary": "Binary file",
    "srec": "Motorola S-record", "java": "Java", "dos": "MS-DOS executable",
}

# --load-opt loader.key=value -> how it is honoured
LOAD_OPTS = {
    "pe.resources": "load_resources",
    "macho.all_slices": "plugin",
    "elf.debug_dir": "post",
    "dsc.modules": "plugin",
}

_SEGMENT = re.compile(
    r"^(?P<name>[^=]+)=(?P<start>[^-:@]+)-(?P<end>[^:@]+)"
    r"(?::(?P<cls>[A-Za-z_]*))?(?::(?P<perm>[rwx-]*))?(?:@(?P<file>.+?)(?::(?P<off>0x[0-9a-fA-F]+|\d+))?)?$"
)


def parse_segment(spec: str) -> dict:
    m = _SEGMENT.match(spec)
    if not m:
        raise usage(f"bad --segment {spec!r}: expected NAME=START-END[:CLASS][:PERM][@FILE[:OFFSET]]")
    start, end = parse_int(m.group("start")), parse_int(m.group("end"))
    if end <= start:
        raise usage(f"bad --segment {spec!r}: end must be above start")
    seg = {"name": m.group("name"), "start": start, "end": end,
           "class": (m.group("cls") or "").upper() or None, "perm": m.group("perm") or None}
    if m.group("file"):
        seg["file"] = m.group("file")
        seg["offset"] = parse_int(m.group("off")) if m.group("off") else 0
    return seg


def build(load: dict[str, Any], settings: Settings, plugin_opts: list[str], log: str | None) -> LoadSpec:
    spec = LoadSpec()
    post: dict[str, Any] = {}
    loader = load.get("loader")
    if loader:
        spec.file_type = LOADERS.get(loader.lower(), loader)
        if loader.lower() == "binary" and not load.get("processor"):
            spec.processor = "metapc"
    if load.get("processor"):
        spec.processor = load["processor"]
    if "base" in load:
        base = int(load["base"])
        if base % 16:
            raise usage(f"--base {base:#x}: must be 16-byte aligned")
        spec.image_base = base
    if "entry" in load:
        spec.entry_point = int(load["entry"])
    if load.get("compiler"):
        spec.compiler = load["compiler"]
    if load.get("no_segmentation"):
        spec.no_segmentation = True
    if load.get("pack"):
        spec.db_compression = {"compress": "compress", "pack": "pack", "none": "no_pack"}[load["pack"]]
    if load.get("bitness"):
        post["bitness"] = int(load["bitness"])
    if load.get("endian"):
        post["endian"] = load["endian"]
    if load.get("segment"):
        post["segments"] = [parse_segment(s) for s in load["segment"]]
    if load.get("svd"):
        post["svd"] = load["svd"]
    if load.get("encoding"):
        post["encoding"] = load["encoding"]
    if load.get("symbols"):
        post["symbols"] = load["symbols"]
    plugin: list[str] = list(plugin_opts)
    for item in load.get("load_opt") or []:
        key, eq, value = item.partition("=")
        if not eq:
            raise usage(f"--load-opt expects loader.key=value, not {item!r}")
        how = LOAD_OPTS.get(key)
        if how is None:
            raise usage(f"--load-opt {key}: unknown option (known: {', '.join(sorted(LOAD_OPTS))})")
        if how == "load_resources":
            spec.load_resources = value.lower() in ("yes", "1", "true", "on")
        elif how == "plugin":
            loader_name, _, opt = key.partition(".")
            plugin.append(f"{loader_name}:{opt}={value}")
        else:
            post.setdefault("load_opts", {})[key] = value
    if plugin:
        spec.plugin_options = " ".join(plugin)
    spec.second_pass_directives = tuple(settings.ida)
    if log:
        spec.log_file = log
    spec.post_load = post
    return spec
