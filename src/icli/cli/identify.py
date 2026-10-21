"""``icli identify``: describe files without creating a database.

Loader acceptance comes from the kernel's own accept_file probes (see
:mod:`icli.cli.local`); format details from LIEF; compiler and packer
from header heuristics; hashes from hashlib, ssdeep and TLSH."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any

from ..errors import IcliError

PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".MPRESS1": "MPRESS",
                   ".MPRESS2": "MPRESS", ".petite": "Petite", ".themida": "Themida", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".nsp0": "NsPack", "PEC2": "PECompact", ".enigma1": "Enigma"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return abs(round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 4))


def _hashes(data: bytes, algos: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for a in algos:
        if a in ("md5", "sha1", "sha256", "sha512"):
            out[a] = hashlib.new(a, data).hexdigest()
        elif a == "ssdeep":
            import ppdeep

            out["ssdeep"] = ppdeep.hash(data)
        elif a == "tlsh":
            import tlsh

            h = tlsh.hash(data)
            out["tlsh"] = h if h and h != "TNULL" else None
    return out


def _arch(binary: Any) -> tuple[str | None, int | None, str | None]:
    try:
        header = binary.abstract.header
        arch = str(header.architecture).split(".")[-1].lower()
        bits = 64 if header.is_64 else 32
        endian = str(header.endianness).split(".")[-1].lower()
        return arch, bits, endian
    except Exception:
        return None, None, None


def _pe(binary: Any, info: dict) -> None:
    import lief

    info["imphash"] = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE) if binary.has_imports else None
    info["n_imports"] = sum(len(lib.entries) for lib in binary.imports)
    info["n_exports"] = len(binary.get_export().entries) if binary.has_exports else 0
    info["signed"] = bool(binary.has_signatures)
    if binary.has_signatures:
        try:
            sig = binary.signatures[0]
            info["signer"] = str(sig.signers[0].issuer) if sig.signers else None
        except Exception:
            info["signer"] = None
    for dbg in binary.debug:
        cv = getattr(dbg, "code_view", None) or (dbg if hasattr(dbg, "filename") else None)
        if cv is not None and hasattr(cv, "filename"):
            guid = getattr(cv, "guid_str", None) or "".join(f"{b:02x}" for b in getattr(cv, "signature", []))
            info["pdb"] = {"path": cv.filename, "guid": guid, "age": getattr(cv, "age", None)}
            break
    if binary.rich_header is not None:
        info["compiler"] = "visual"
    names = [s.name for s in binary.sections]
    for n in names:
        if n in PACKER_SECTIONS:
            info["packer"] = PACKER_SECTIONS[n]
            break


def _elf(binary: Any, info: dict, data: bytes) -> None:
    info["n_imports"] = sum(1 for s in binary.dynamic_symbols if s.is_function and not s.value)
    info["n_exports"] = sum(1 for s in binary.exported_symbols)
    info["signed"] = False
    for note in binary.notes:
        if str(note.type).endswith("BUILD_ID"):
            info["build_id"] = bytes(note.description).hex()
    comment = binary.get_section(".comment")
    if comment is not None:
        text = bytes(comment.content).decode("latin-1")
        info["compiler"] = "clang" if "clang" in text.lower() else ("gcc" if "GCC" in text else None)
    if b"UPX!" in data[:4096] or any(s.name.startswith("UPX") for s in binary.sections):
        info["packer"] = "UPX"


def _macho(binary: Any, info: dict) -> None:
    info["n_imports"] = sum(1 for s in binary.imported_symbols)
    info["n_exports"] = sum(1 for s in binary.exported_symbols)
    info["signed"] = bool(binary.has_code_signature)
    if binary.has_uuid:
        info["build_id"] = "".join(f"{b:02x}" for b in binary.uuid.uuid)
    info["compiler"] = "clang"


def identify(path: Path, algos: list[str], *, deep: bool = False) -> dict:
    from . import local

    data = path.read_bytes()
    info: dict[str, Any] = {"_t": "identify", "path": str(path), "size": len(data), "entropy": entropy(data)}
    try:
        loaders = local.loaders_for(path)
    except IcliError:  # no IDA, no licence: say so rather than "unrecognised"
        raise
    except Exception:
        loaders = []
    info["loader"] = loaders[0]["loader"] if loaders else None
    info["loaders"] = [x["loader"] for x in loaders]
    info["format"] = loaders[0]["format"] if loaders else None
    info["formats"] = [x["format"] for x in loaders]
    info.update({"arch": None, "bitness": None, "endian": None, "compiler": None, "packer": None,
                 "sections": [], "imphash": None, "pdb": None, "build_id": None, "signed": None, "signer": None,
                 "n_imports": None, "n_exports": None})
    if loaders and loaders[0].get("processor"):
        info["arch"] = loaders[0]["processor"]
    try:
        import lief

        lief.logging.disable()
        binary = lief.parse(str(path))
    except Exception:
        binary = None
    if binary is not None:
        arch, bits, endian = _arch(binary)
        info["arch"], info["bitness"], info["endian"] = arch or info["arch"], bits, endian
        secs = []
        for s in binary.sections:
            content = bytes(s.content) if s.size and s.size < (256 << 20) else b""
            secs.append({"name": s.name, "size": int(s.size), "entropy": entropy(content)})
        info["sections"] = secs
        try:
            if isinstance(binary, lief.PE.Binary):
                _pe(binary, info)
            elif isinstance(binary, lief.ELF.Binary):
                _elf(binary, info, data)
            elif isinstance(binary, lief.MachO.Binary):
                _macho(binary, info)
        except Exception:  # malformed headers: keep what we have
            pass
        if info["packer"] is None and any(s["entropy"] > 7.6 and s["size"] > 4096 for s in secs):
            info["packer"] = "unknown (high entropy)"
    info.update(_hashes(data, algos))
    if deep and loaders:
        info.update(_deep(path))
    return info


def _deep(path: Path) -> dict:
    """Run the loader and analysis in a scratch database to count objects."""
    from .opening import open_session
    from .options import GlobalOptions

    g = GlobalOptions()
    g.no_cache = True
    g.output.quiet = True
    s = open_session(str(path), g, lambda *a: None)
    try:
        info = s.call("info", {})["records"][0]
    finally:
        s.close(save=False)
    return {"n_functions": info["counts"]["functions"]["total"], "n_strings": info["counts"]["strings"]}
