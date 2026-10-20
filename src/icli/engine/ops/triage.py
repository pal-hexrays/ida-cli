"""info, status, lifecycle bookkeeping."""

from __future__ import annotations

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idc

from .. import lifecycle, typesupport
from ..addresses import entry_point
from ..context import A, Ctx
from ..kinds import KINDS
from ..kinds.types import applied_signatures
from ..rpc import op


def _endian() -> str:
    return "big" if ida_ida.inf_is_be() else "little"


def _bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)


def _compiler() -> dict:
    cc = ida_ida.inf_get_cc_id()
    name = ida_typeinf.get_compiler_name(cc) or ""
    abbr = ida_typeinf.get_compiler_abbr(cc) or ""
    abi = ida_ida.inf_get_abibits() if hasattr(ida_ida, "inf_get_abibits") else 0
    return {"name": name, "id": abbr, "abibits": abi}


@op("info")
def info(ctx: Ctx, cache_key: str | None = None) -> dict:
    total = lib = named = thunk = 0
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        total += 1
        if f.flags & ida_funcs.FUNC_LIB:
            lib += 1
        if f.flags & ida_funcs.FUNC_THUNK:
            thunk += 1
        if ida_bytes.has_user_name(ida_bytes.get_flags(f.start_ea)):
            named += 1
    entries = [A(it.ea) for it in KINDS["entry"].all(ctx)]
    md5 = ida_nalt.retrieve_input_file_md5()
    sha = ida_nalt.retrieve_input_file_sha256()
    til = ida_typeinf.get_idati()
    tils = [til.base(i).name for i in range(til.nbases)]
    lc = lifecycle.info()
    return {
        "_t": "info",
        "input": ida_nalt.get_input_file_path() or ida_nalt.get_root_filename(),
        "db": idc.get_idb_path(),
        "size": ida_nalt.retrieve_input_file_size(),
        "md5": md5.hex() if md5 else None,
        "sha256": sha.hex() if sha else None,
        "crc32": ida_nalt.retrieve_input_file_crc32(),
        "loader": ida_loader.get_file_type_name(),
        "format": idc.get_inf_attr(idc.INF_FILETYPE),
        "processor": ida_ida.inf_get_procname(),
        "bitness": _bitness(),
        "endian": _endian(),
        "compiler": _compiler(),
        "image_base": A(ida_nalt.get_imagebase()),
        "entry": A(entry_point()),
        "entries": entries,
        "min_ea": A(ida_ida.inf_get_min_ea()),
        "max_ea": A(ida_ida.inf_get_max_ea()),
        "counts": {
            "segments": ida_segment.get_segm_qty(),
            "functions": {"total": total, "library": lib, "named": named, "thunk": thunk},
            "strings": sum(1 for _ in ctx.db.strings),
            "types": len(typesupport.local_types()),
            "names": ida_name.get_nlist_size(),
        },
        "signatures": [s["name"] for s in applied_signatures()],
        "tils": tils,
        "debug_info": _debug_info(),
        "state": lc["state"],
        "passes": lc["passes"],
        "kernel": ida_kernwin.get_kernel_version(),
        "ida_version_created": _db_version(),
        "cache_key": cache_key,
    }


def _db_version() -> str | None:
    try:
        return str(ida_ida.inf_get_version())
    except Exception:
        return None


def _debug_info() -> list[str]:
    out = []
    import ida_netnode

    for name, label in (("$ pdb", "pdb"), ("$ dwarf", "dwarf")):
        n = ida_netnode.netnode(name, 0, False)
        if n != ida_netnode.BADNODE:
            out.append(label)
    return out


@op("status")
def status(ctx: Ctx, lock: dict | None = None, journal_len: int | None = None) -> dict:
    from .. import journal

    lc = lifecycle.info()
    rec = {
        "_t": "status",
        "state": lc["state"],
        "passes": lc["passes"],
        "auto_is_ok": bool(ida_auto.auto_is_ok()),
        "pending": lifecycle.pending(),
        "journal": journal.length(),
        "revision": journal.revision(),
        "lock": lock,
        "db": idc.get_idb_path(),
    }
    if lc["state"] not in ("analyzed", "enriched"):
        ctx.set_status(3)
    return rec


@op("lifecycle.mark")
def lifecycle_mark(ctx: Ctx, **fields: object) -> dict:
    d = lifecycle.mark(**fields)
    return {"_t": "lifecycle", **d, "state": lifecycle.state()}


@op("lifecycle.state")
def lifecycle_state(ctx: Ctx) -> dict:
    return {"_t": "lifecycle", **lifecycle.info(), "auto_is_ok": bool(ida_auto.auto_is_ok())}

