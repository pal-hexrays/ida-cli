"""Environment, IDA installation and per-user directory discovery.

No IDA module is imported here: the client process stays IDA-free.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys
from functools import lru_cache
from pathlib import Path


def env(name: str, default: str | None = None) -> str | None:
    """``ICLI_<name>``."""
    v = os.environ.get("ICLI_" + name)
    return v if v else default


def idausr() -> Path:
    v = os.environ.get("IDAUSR")
    if v:
        return Path(v.split(os.pathsep)[0]).expanduser()
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", "~")).expanduser() / "Hex-Rays" / "IDA Pro"
    return Path("~/.idapro").expanduser()


def icli_home() -> Path:
    """Where icli keeps its own files (icli.toml, recipes): ICLI_HOME, else
    the first IDAUSR directory."""
    v = os.environ.get("ICLI_HOME")
    return Path(v).expanduser() if v else idausr()


@lru_cache(maxsize=1)
def idadir() -> Path | None:
    v = os.environ.get("IDADIR")
    candidates: list[Path] = []
    if v:
        candidates.append(Path(v).expanduser())
    cfg = idausr() / "ida-config.json"
    try:
        data = json.loads(cfg.read_text())
        p = data.get("Paths", {}).get("ida-install-dir")
        if p:
            candidates.append(Path(p).expanduser())
    except (OSError, ValueError):
        pass
    for c in candidates:
        if c.suffix == ".app" and (c / "Contents" / "MacOS").is_dir():
            c = c / "Contents" / "MacOS"
        if c.is_dir():
            return c
    return None


IDALIB = {"darwin": "libidalib.dylib", "win32": "idalib.dll"}.get(sys.platform, "libidalib.so")


def require_ida() -> Path:
    """The IDA installation, or a usage-level error saying how to provide one."""
    from ..errors import Exit, IcliError

    d = idadir()
    if d is None or not (d / IDALIB).is_file():
        where = f" ({d} has no {IDALIB})" if d is not None else ""
        raise IcliError(
            Exit.LICENSE,
            f"IDA Pro was not found{where}. icli needs IDA Pro 9.0 or later with idalib. "
            "Set IDADIR to the IDA folder, or run IDA's py-activate-idalib.py once.",
            "NOIDA",
        )
    return d


@lru_cache(maxsize=1)
def kernel_version() -> str:
    """The installed IDA version, read from the installation (no kernel load)."""
    d = idadir()
    if d is None:
        return "unknown"
    plist = d.parent / "Info.plist"
    if plist.is_file():
        try:
            with plist.open("rb") as fh:
                info = plistlib.load(fh)
            v = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            if v:
                return str(v)
        except Exception:
            pass
    for name in ("python/ida_pro.py",):
        p = d / name
        if p.is_file():
            import re

            m = re.search(r"IDA_SDK_VERSION\s*=\s*(\d+)", p.read_text(errors="replace"))
            if m:
                n = int(m.group(1))
                return f"{n // 100}.{n % 100 // 10}"
    return d.name


def cache_dir() -> Path:
    v = env("CACHE_DIR")
    if v:
        return Path(v).expanduser()
    from .config import CONFIG

    cfg = CONFIG.get("cache", {}).get("dir")
    if cfg:
        return Path(cfg).expanduser()
    if sys.platform == "darwin":
        return Path("~/Library/Caches/icli").expanduser()
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", "~")).expanduser() / "icli"
    base = os.environ.get("XDG_CACHE_HOME") or "~/.cache"
    return Path(base).expanduser() / "icli"


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    root = Path(base) if base else Path(os.environ.get("TMPDIR", "/tmp"))
    return root / f"icli-{os.getuid()}" if hasattr(os, "getuid") and not base else root / "icli"


def author() -> str:
    return env("AUTHOR") or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
