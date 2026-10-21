"""In-process idalib, for commands that need the kernel but no database
(identify, loaders, processors, --version) and for offline database
maintenance (db pack/unpack/gc/check).

``build_loaders_list`` and ``get_idp_descs`` are not exposed to Python; they
are C exports of the kernel library and are called through ctypes with the
structure layouts of the SDK headers (loader.hpp)."""

from __future__ import annotations

import contextlib
import ctypes
import datetime as _dt
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from ..errors import Exit, IcliError
from .env import idadir, idausr


class _QString(ctypes.Structure):
    _fields_ = [("array", ctypes.c_char_p), ("n", ctypes.c_size_t), ("alloc", ctypes.c_size_t)]

    def text(self) -> str:
        return (self.array or b"").decode("utf-8", "replace")


class _LoadInfo(ctypes.Structure):
    pass


_LoadInfo._fields_ = [
    ("next", ctypes.POINTER(_LoadInfo)),
    ("dllname", _QString),
    ("ftypename", _QString),
    ("processor", _QString),
    ("ftype", ctypes.c_int),
    ("loader_flags", ctypes.c_uint32),
    ("lflags", ctypes.c_uint32),
    ("pri", ctypes.c_int),
]


class _QVector(ctypes.Structure):
    _fields_ = [("array", ctypes.c_void_p), ("n", ctypes.c_size_t), ("alloc", ctypes.c_size_t)]


class _IdpName(ctypes.Structure):
    _fields_ = [("lname", _QString), ("sname", _QString), ("hidden", ctypes.c_bool)]


class _IdpDesc(ctypes.Structure):
    _fields_ = [("path", _QString), ("mtime", ctypes.c_int64), ("family", _QString), ("names", _QVector),
                ("is_script", ctypes.c_bool), ("checked", ctypes.c_bool)]


@lru_cache(maxsize=1)
def kernel() -> ctypes.CDLL:
    """Initialise idalib in this process (no database) and return libida."""
    if idadir() is None:
        raise IcliError(Exit.LICENSE, "IDA installation not found (set IDADIR or run py-activate-idalib.py)",
                        "NOIDA")
    try:
        import idapro  # noqa: F401  (initialises the kernel)
    except Exception as error:  # noqa: BLE001 - licence and installation problems
        raise IcliError(Exit.LICENSE, f"cannot initialise idalib: {error}", "LICENSE")
    names = {"darwin": "libida.dylib", "win32": "ida.dll"}.get(sys.platform, "libida.so")
    lib = ctypes.CDLL(str(idadir() / names))
    lib.build_loaders_list.restype = ctypes.POINTER(_LoadInfo)
    lib.build_loaders_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.free_loaders_list.argtypes = [ctypes.POINTER(_LoadInfo)]
    lib.open_linput.restype = ctypes.c_void_p
    lib.open_linput.argtypes = [ctypes.c_char_p, ctypes.c_bool]
    lib.close_linput.argtypes = [ctypes.c_void_p]
    lib.get_idp_descs.restype = ctypes.POINTER(_QVector)
    return lib


def loaders_for(path: Path) -> list[dict]:
    """Loaders accepting ``path``, in the order the GUI offers them."""
    lib = kernel()
    li = lib.open_linput(str(path).encode(), False)
    if not li:
        raise IcliError(Exit.NOT_FOUND, f"{path}: cannot open", "NOTFOUND")
    try:
        head = lib.build_loaders_list(li, str(path).encode())
        out = []
        node = head
        while node:
            info = node.contents
            dll = Path(info.dllname.text()).name
            out.append({"loader": dll.rsplit(".", 1)[0] if not dll.endswith((".py", ".idc")) else dll,
                        "format": info.ftypename.text(), "processor": info.processor.text() or None,
                        "archive": bool(info.lflags & 1), "priority": info.pri})
            node = info.next
        if head:
            lib.free_loaders_list(head)
        return out
    finally:
        lib.close_linput(li)


def all_loaders() -> list[dict]:
    d = idadir()
    out = []
    if d is None:
        return out
    for p in sorted((d / "loaders").iterdir()):
        if p.suffix in (".dylib", ".so", ".dll", ".py", ".idc"):
            out.append({"loader": p.stem if p.suffix in (".dylib", ".so", ".dll") else p.name, "path": str(p),
                        "script": p.suffix in (".py", ".idc")})
    return out


DECOMPILER_PLUGINS = {
    "hexx64": ("x86/x64", ("metapc",)), "hexarm": ("ARM/ARM64", ("arm",)), "hexmips": ("MIPS", ("mips",)),
    "hexppc": ("PowerPC", ("ppc",)), "hexrv": ("RISC-V", ("riscv",)), "hexv850": ("V850", ("v850",)),
    "hexarc": ("ARC", ("arc",)), "hexqdsp6": ("Hexagon", ("hexagon",)), "hextricore": ("TriCore", ("tricore",)),
    "hexdalvik": ("Dalvik", ("dalvik",)),
}


def installed_decompilers() -> dict[str, str]:
    d = idadir()
    out = {}
    if d is None:
        return out
    for stem, (label, _) in DECOMPILER_PLUGINS.items():
        if any((d / "plugins" / f"{stem}{ext}").exists() for ext in (".dylib", ".so", ".dll")):
            out[stem] = label
    return out


def processors() -> list[dict]:
    lib = kernel()
    vec = lib.get_idp_descs()
    if not vec:
        return []
    descs = ctypes.cast(vec.contents.array, ctypes.POINTER(_IdpDesc))
    decompilers = installed_decompilers()
    out = []
    for i in range(vec.contents.n):
        d = descs[i]
        names = ctypes.cast(d.names.array, ctypes.POINTER(_IdpName))
        module = Path(d.path.text()).stem
        variants = [{"name": names[j].sname.text(), "description": names[j].lname.text(),
                     "hidden": bool(names[j].hidden)} for j in range(d.names.n)]
        has_dec = [label for stem, (label, procs) in DECOMPILER_PLUGINS.items()
                   if stem in decompilers and (module in procs or any(v["name"] in procs for v in variants))]
        out.append({"module": module, "family": d.family.text(), "path": d.path.text(), "script": bool(d.is_script),
                    "variants": variants, "decompiler": has_dec[0] if has_dec else None,
                    "assembler": module in ("metapc", "arm", "mips", "ppc", "pc")})
    return out


# -- licences ---------------------------------------------------------------------------------

EDITIONS = {"ida-pro": "Pro", "ida-home": "Home", "ida-free": "Free", "ida-pro-classroom": "Classroom",
            "ida-essential": "Essential", "ida-classroom": "Classroom"}
ADDON_DECOMPILERS = {"HEXX86": "x86", "HEXX64": "x64", "HEXARM": "ARM", "HEXARM64": "ARM64", "HEXMIPS": "MIPS",
                     "HEXMIPS64": "MIPS64", "HEXPPC": "PowerPC", "HEXPPC64": "PowerPC64", "HEXRV": "RISC-V",
                     "HEXRV64": "RISC-V64", "HEXV850": "V850", "HEXARC": "ARC", "HEXQDSP6": "Hexagon",
                     "HEXTRICORE": "TriCore", "HEXCLOUD": "cloud"}


def licences() -> list[dict]:
    today = _dt.date.today().isoformat()
    out = []
    for p in sorted(idausr().glob("*.hexlic")):
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        for lic in data.get("payload", {}).get("licenses", []):
            end = lic.get("end_date") or ""
            out.append({"id": lic.get("id"), "edition": EDITIONS.get(lic.get("edition_id", ""), lic.get("edition_id")),
                        "end": end, "valid": not end or end[:10] >= today, "file": p.name,
                        "decompilers": sorted({ADDON_DECOMPILERS.get(a.get("code", ""), a.get("code", ""))
                                               for a in lic.get("add_ons", []) if isinstance(a, dict)})})
    return out


def edition_info() -> dict:
    valid = [x for x in licences() if x["valid"]]
    editions = sorted({x["edition"] for x in valid})
    codes = {d for x in valid for d in x["decompilers"]}
    features = sorted(c for c in codes if c in ("LUMINA", "TEAMS"))
    cloud = sorted(c[4:] for c in codes if c.startswith("HEXC"))
    local_ = sorted(c for c in codes if c not in features and not c.startswith("HEXC"))
    return {"edition": ", ".join(editions) if editions else "no valid licence", "decompilers": local_,
            "cloud_decompilers": cloud, "features": features, "licences": valid}


# -- offline database access ---------------------------------------------------------------------


@contextlib.contextmanager
def local_database(path: Path, args: str = "", *, save: bool = True) -> Iterator[Any]:
    """Open a database in this process (no worker); refuses one in use."""
    from ida_nexus import find_database_owner

    if find_database_owner(str(path)) is not None:
        raise IcliError(Exit.LOCKED, f"{path}: database is open in another process", "LOCKED")
    kernel()
    import idapro

    rc = idapro.open_database(str(path), False, args)
    if rc != 0:
        raise IcliError(Exit.CORRUPT if path.suffix in (".i64", ".idb") else Exit.LOAD,
                        f"{path}: cannot open (error {rc})", "OPEN")
    try:
        yield idapro
    except BaseException:
        idapro.close_database(False)
        raise
    else:
        idapro.close_database(save)


@contextlib.contextmanager
def scratch_database() -> Iterator[Any]:
    """An empty throw-away database, for kernel APIs that require one
    (type library work without a target)."""
    import tempfile

    kernel()
    import idapro

    d = Path(tempfile.mkdtemp(prefix="icli-scratch-"))
    blob = d / "scratch.bin"
    blob.write_bytes(b"\x90" * 16)
    rc = idapro.open_database(str(blob), False, "-Tbinary -pmetapc")
    if rc != 0:
        raise IcliError(Exit.INTERNAL, f"cannot create a scratch database (error {rc})", "INTERR")
    try:
        yield idapro
    finally:
        idapro.close_database(False)
        import shutil

        shutil.rmtree(d, ignore_errors=True)


def _repair_input_path(idb: Path) -> None:
    """Old databases may store the input path in a legacy 8-bit encoding,
    which idalib (and ida-nexus) cannot decode: rewrite it as UTF-8."""
    import ida_nalt

    try:
        ida_nalt.get_input_file_path()
        ida_nalt.get_root_filename()
    except UnicodeDecodeError:
        ida_nalt.set_root_filename(str(idb.with_suffix("")))


def upgrade_idb(idb: Path, out: Path | None = None) -> Path:
    """Convert a legacy .idb to .i64: idalib upgrades it when opening, and
    saving writes the .i64 next to it.  Returns the .i64 path."""
    import shutil

    target = idb.with_suffix(".i64")
    if target.exists() and out is None:
        return target
    with local_database(idb, ""):
        _repair_input_path(idb)
    if not target.exists():
        raise IcliError(Exit.CORRUPT, f"{idb}: the kernel did not produce {target.name}", "UPGRADE")
    for leftover in (idb.with_suffix(".id0.upgrade.log"),):
        leftover.unlink(missing_ok=True)
    if out is not None and out.resolve() != target.resolve():
        shutil.move(str(target), str(out))
        return out
    return target
