"""Knowledge: FLIRT signatures, type libraries, Lumina, and ``load`` sources."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import ida_auto
import ida_bytes
import ida_fixup
import ida_funcs
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_typeinf
import ida_ua

from ...errors import Exit, IcliError
from .. import edits, select
from ..context import A, Ctx
from ..kinds.functions import chunks
from ..kinds.types import applied_signatures
from ..rpc import op
from .common import selection

BADADDR = ida_idaapi.BADADDR


# -- FLIRT ------------------------------------------------------------------------------------


def _sig_dirs() -> list[Path]:
    import ida_diskio

    proc = ida_ida.inf_get_procname().lower()
    sub = {"metapc": "pc"}.get(proc, proc)
    out = []
    user = os.environ.get("IDAUSR")
    bases = [Path(user.split(os.pathsep)[0])] if user else [Path("~/.idapro").expanduser()]
    bases.append(Path(ida_diskio.idadir("")))
    for b in bases:
        out.append(b / "sig" / sub)
    return out


def resolve_sig(name: str) -> str:
    """A .sig by path, or by name in $IDAUSR/sig/<proc> then $IDADIR/sig/<proc>."""
    p = Path(name)
    if p.suffix == "":
        p = p.with_suffix(".sig")
    if p.is_absolute() or p.exists():
        if not p.exists():
            raise IcliError(Exit.NOT_FOUND, f"{name}: signature file not found", "NOTFOUND")
        return str(p.resolve())
    for d in _sig_dirs():
        if (d / p.name).exists():
            return p.stem
    raise IcliError(Exit.NOT_FOUND, f"{name}: no such signature in {', '.join(str(d) for d in _sig_dirs())}",
                    "NOTFOUND")


def apply_signature(name: str, *, plan_only: bool = False) -> dict:
    sig = resolve_sig(name)
    before = {s["name"]: s["matches"] for s in applied_signatures()}
    if ida_funcs.plan_to_apply_idasgn(sig) == 0:
        raise IcliError(Exit.LOAD, f"{name}: cannot apply signature", "LOAD")
    if plan_only:
        return {"_t": "sig", "name": name, "status": "planned"}
    ida_auto.auto_wait()
    after = applied_signatures()
    rec = next((s for s in after if Path(s["name"]).stem == Path(sig).stem), None)
    matches = rec["matches"] if rec else 0
    return {"_t": "sig", "name": name, "file": sig, "matches": matches,
            "new": matches - before.get(rec["name"], 0) if rec else 0, "title": rec["title"] if rec else None}


def startup_signatures() -> list[str]:
    """Signatures IDA's autoload.cfg proposes for this file's format/compiler."""
    import ida_diskio

    proc = ida_ida.inf_get_procname().lower()
    sub = {"metapc": "pc"}.get(proc, proc)
    cfg = Path(ida_diskio.idadir("")) / "sig" / sub / "autoload.cfg"
    if not cfg.exists():
        return []
    ftype = (ida_loader.get_file_type_name() or "").lower()
    comp = (ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id()) or "").lower()
    out: list[str] = []
    for line in cfg.read_text(errors="replace").splitlines():
        line = line.split(";", 1)[0].strip()
        if not line or line.startswith("["):
            continue
        m = re.match(r"^(\S+\.sig)\s+(.*)$", line, re.I)
        if not m:
            continue
        sig, desc = m.group(1), m.group(2).lower()
        words = [w for w in re.findall(r"[a-z0-9+]+", desc) if len(w) > 2]
        if any(w in ftype or w in comp for w in words):
            out.append(Path(sig).stem)
    return out


@op("sig.apply")
def sig_apply(ctx: Ctx, names: list[str]) -> list[dict]:
    ctx.require_writable()
    if names == ["auto"]:
        names = startup_signatures()
        if not names:
            ctx.warn("NOMATCH", "no startup signatures apply to this file")
    out = [apply_signature(n) for n in names]
    return out


@op("sig.lib_functions")
def sig_lib_functions(ctx: Ctx) -> list[dict]:
    """Library functions (what applying signatures produced), for sig match."""
    out = []
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if f.flags & ida_funcs.FUNC_LIB:
            out.append({"_t": "match", "ea": A(f.start_ea), "name": ida_funcs.get_func_name(f.start_ea)})
    return out


def _crc16(data: bytes) -> int:
    """FLIRT's CRC16 (X.25: reflected 0x8408, init/xorout 0xFFFF)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    crc = ~crc & 0xFFFF
    return ((crc << 8) & 0xFF00) | (crc >> 8)


def _variable_mask(start: int, end: int) -> list[bool]:
    """Bytes that change with relocation: fixups, and address operands."""
    mask = [False] * (end - start)
    ea = ida_fixup.get_next_fixup_ea(start - 1) if start else ida_fixup.get_first_fixup_ea()
    while ea != BADADDR and ea < end:
        fd = ida_fixup.fixup_data_t()
        if fd.get(ea):
            size = max(1, ida_fixup.calc_fixup_size(fd.get_type()))
            for i in range(ea - start, min(ea - start + size, end - start)):
                if i >= 0:
                    mask[i] = True
        ea = ida_fixup.get_next_fixup_ea(ea)
    insn = ida_ua.insn_t()
    lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    ea = start
    while ea < end:
        n = ida_ua.decode_insn(insn, ea)
        if n <= 0:
            ea += 1
            continue
        for opnd in insn.ops:
            if opnd.type == ida_ua.o_void:
                break
            addr_like = opnd.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far) or (
                opnd.type in (ida_ua.o_imm, ida_ua.o_displ) and lo <= (opnd.value or opnd.addr) < hi
                and (opnd.value or opnd.addr) > 0x1000)
            if addr_like and opnd.offb:
                width = ida_ua.get_dtype_size(opnd.dtype) if opnd.type != ida_ua.o_near else n - opnd.offb
                for i in range(ea - start + opnd.offb, min(ea - start + opnd.offb + width, end - start)):
                    mask[i] = True
        ea += n
    return mask


def pattern_line(f: Any) -> str | None:
    """One FLIRT .pat line for a function (first chunk)."""
    start, end = chunks(f)[0]
    data = ida_bytes.get_bytes(start, end - start) or b""
    if len(data) < 8:
        return None
    mask = _variable_mask(start, end)
    head = "".join(".." if mask[i] else f"{data[i]:02X}" for i in range(min(32, len(data))))
    head = head.ljust(64, ".")
    alen = 0
    for i in range(32, min(len(data), 32 + 255)):
        if mask[i]:
            break
        alen += 1
    crc = _crc16(data[32:32 + alen]) if alen else 0
    name = ida_funcs.get_func_name(start) or f"sub_{start:x}"
    names = [f":0000 {name}"]
    import ida_xref

    for off in range(len(data)):
        ea = start + off
        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(ea, ida_xref.XREF_NOFLOW)
        while ok:
            if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                target = ida_name.get_name(xb.to)
                insn = ida_ua.insn_t()
                if target and ida_ua.decode_insn(insn, ea) and not target.startswith(("sub_", "loc_")):
                    names.append(f"^{off + insn.ops[0].offb:04X} {target}")
            ok = xb.next_from()
    tail_start = 32 + alen
    tail = "".join(".." if mask[i] else f"{data[i]:02X}" for i in range(tail_start, len(data)))
    return f"{head} {alen:02X} {crc:04X} {len(data):04X} {' '.join(names)}" + (f" {tail}" if tail else "")


@op("sig.patterns")
def sig_patterns(ctx: Ctx, selectors: list[dict] | None = None) -> list[dict]:
    from ..kinds import KINDS

    fk = KINDS["function"]
    import ida_segment

    def real_code(it: Any) -> bool:
        seg = ida_segment.getseg(it.ea)
        return seg is None or seg.type not in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP)

    funcs = list(select.functions_of(ctx, select.evaluate(ctx, selectors))) if selectors else [
        it for it in fk.all(ctx) if not fk.get(it, "thunk", ctx)]
    funcs = [f for f in funcs if real_code(f)]
    lines = []
    skipped = 0
    for fi in funcs:
        line = pattern_line(fi.obj)
        if line is None:
            skipped += 1
            continue
        lines.append(line)
    if skipped:
        ctx.warn("SKIPPED", f"{skipped} function(s) too short for a pattern")
    return [{"_t": "pat", "functions": len(lines), "text": "\n".join(lines) + "\n---\n"}]


# -- type libraries ------------------------------------------------------------------------------


@op("til.export")
def til_export(ctx: Ctx, path: str, description: str | None = None) -> dict:
    from .. import typesupport

    target = Path(path)
    til = ida_typeinf.new_til(target.name, description or "local types")
    ida_typeinf.enable_numbered_types(til, True)  # copy_named_type needs ordinals
    n = 0
    for _, name, _tif in typesupport.local_types():
        if ida_typeinf.copy_named_type(til, ida_typeinf.get_idati(), name):
            n += 1
    ida_typeinf.compact_til(til)
    if not ida_typeinf.store_til(til, None, str(target.resolve())) or not target.exists():
        raise IcliError(Exit.INTERNAL, f"{path}: cannot write type library", "INTERR")
    ida_typeinf.free_til(til)
    return {"_t": "til", "path": str(target), "types": n}


# -- Lumina -----------------------------------------------------------------------------------------


def _lumina() -> Any:
    try:
        import ida_lumina
    except ImportError:
        raise IcliError(Exit.LICENSE, "this IDA has no Lumina support", "LICENSE")
    conn = ida_lumina.get_server_connection()
    if conn is None:
        raise IcliError(Exit.NETWORK, "cannot connect to the Lumina server (configured in IDA: Options > General > Lumina)", "NETWORK")
    return ida_lumina, conn


def _eavec(eas: list[int]) -> Any:
    import ida_pro

    v = ida_pro.eavec_t()
    for ea in eas:
        v.push_back(ea)
    return v


def lumina_pull(ctx: Ctx, selectors: list[dict] | None, *, apply: bool = False) -> list[dict]:
    ida_lumina, conn = _lumina()
    from ..kinds import KINDS

    fk = KINDS["function"]
    funcs = [it.ea for it in (select.functions_of(ctx, select.evaluate(ctx, selectors)) if selectors
                              else fk.all(ctx))]
    res = conn.pull_md(_eavec(funcs), 0)
    if res is None:
        raise IcliError(Exit.NETWORK, "Lumina pull failed", "NETWORK")
    out = []
    results = list(res.results)
    codes = list(res.codes)
    ri = 0
    for ea, code in zip(funcs, codes):
        if code != getattr(ida_lumina, "PDRES_OK", 1) and code <= 0:
            continue
        if ri >= len(results):
            break
        fi = results[ri]
        ri += 1
        md = ida_lumina.split_metadata(bytes(fi.metadata)) if hasattr(fi, "metadata") else {}
        proto = None
        tif = ida_typeinf.tinfo_t()
        if hasattr(fi, "metadata") and ida_lumina.extract_type_from_metadata(tif, fi.metadata):
            proto = str(tif)
        rec = {"_t": "lumina", "ea": A(ea), "current": ida_funcs.get_func_name(ea), "name": fi.name,
               "type": f"{proto}" if proto else None, "score": round(ida_lumina.score_metadata(fi) / 100.0, 3)
               if hasattr(ida_lumina, "score_metadata") else None,
               "frequency": getattr(fi, "frequency", None), "keys": sorted(str(k) for k in md) if md else []}
        out.append(rec)
        if apply:
            ctx.require_writable()
            before = ida_funcs.get_func_name(ea)
            ida_lumina.apply_metadata(ea, fi, getattr(ida_lumina, "AMDF_UPGRADE", 0))
            after = ida_funcs.get_func_name(ea)
            edits.record_change(ctx, {"_t": "edit", "kind": "name", "ea": A(ea), "before": before, "after": after},
                                kind="name", ea=ea, key=None, before=before, after=after)
            rec["applied"] = True
    if apply:
        from .. import lifecycle

        lifecycle.mark(enriched=["lumina"])
    return out


@op("lumina.pull")
def lumina_pull_op(ctx: Ctx, selectors: list[dict] | None = None, apply: bool = False) -> list[dict]:
    return lumina_pull(ctx, selectors, apply=apply)


@op("lumina.push")
def lumina_push(ctx: Ctx, selectors: list[dict] | None = None) -> list[dict]:
    ida_lumina, conn = _lumina()
    from ..kinds import KINDS

    fk = KINDS["function"]
    items = list(select.functions_of(ctx, select.evaluate(ctx, selectors))) if selectors else list(fk.all(ctx))
    named = [it for it in items if fk.get(it, "named", ctx) and not fk.get(it, "dummy", ctx)]
    refused = [fk.get(it, "name", ctx) for it in items if it not in named]
    if refused and selectors:
        ctx.warn("DUMMY", f"not pushing {len(refused)} function(s) with dummy names")
    if not named:
        raise IcliError(Exit.EMPTY_SELECTION, "no user-named functions to push", "NOMATCH")
    result = ida_lumina.push_md_result_t() if hasattr(ida_lumina, "push_md_result_t") else None
    opts = ida_lumina.push_md_opts_t() if hasattr(ida_lumina, "push_md_opts_t") else None
    if result is None or opts is None:
        raise IcliError(Exit.LICENSE, "this IDA's Lumina API cannot push", "LICENSE")
    if hasattr(opts, "eas"):
        for it in named:
            opts.eas.push_back(it.ea)
    if not conn.push_md(result, opts):
        raise IcliError(Exit.NETWORK, "Lumina push failed", "NETWORK")
    return [{"_t": "lumina", "ea": A(it.ea), "name": fk.get(it, "name", ctx), "pushed": True} for it in named]


@op("lumina.del")
def lumina_del(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    _, conn = _lumina()
    funcs = [it.ea for it in select.functions_of(ctx, selection(ctx, selectors))]
    if not conn.del_history(_eavec(funcs)):
        raise IcliError(Exit.NETWORK, "Lumina delete failed", "NETWORK")
    return [{"_t": "lumina", "ea": A(ea), "deleted": True} for ea in funcs]


@op("lumina.history")
def lumina_history(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    """The metadata versions the server holds for each function."""
    return lumina_pull(ctx, selectors, apply=False)


# -- load ----------------------------------------------------------------------------------------------


def load_debug_info(src: str) -> dict:
    """--symbols / load pdb|dwarf: PDB files, separate DWARF, dSYM bundles."""
    p = Path(src)
    if src in ("auto",):
        return {"_t": "load", "option": "symbols", "value": "auto"}
    if src in ("symsrv", "debuginfod"):
        return _plugin_load("pdb" if src == "symsrv" else "dwarf", None, src)
    if not p.exists():
        raise IcliError(Exit.NOT_FOUND, f"{src}: no such file", "NOTFOUND")
    kind = "pdb" if p.suffix.lower() == ".pdb" else "dwarf"
    return _plugin_load(kind, p, src)


def _plugin_load(kind: str, path: Path | None, src: str) -> dict:
    import ida_netnode

    if kind == "pdb":
        n = ida_netnode.netnode("$ pdb", 0, True)
        if path is not None:
            n.supset(0, str(path))  # PDB plugin: file to load
        ok = ida_loader.load_and_run_plugin("pdb", 3 if path is not None else 1)
    else:
        if path is not None:
            n = ida_netnode.netnode("$ dwarf_params", 0, True)
            n.supset(1, str(path))
        ok = ida_loader.load_and_run_plugin("dwarf", 3 if path is not None else 0)
    ida_auto.auto_wait()
    return {"_t": "load", "kind": kind, "source": src, "status": "ok" if ok else "failed"}


@op("load")
def load(ctx: Ctx, kind: str, path: str | None = None, at: int | None = None, text: str | None = None,
         records: list[dict] | None = None, name: str | None = None) -> list[dict]:
    ctx.require_writable()
    if kind in ("pdb", "dwarf"):
        return [load_debug_info(path or "auto")]
    if kind == "svd":
        from .analysis import load_svd

        return [{"_t": "load", "kind": "svd", "registers": load_svd(path)}]
    if kind == "idc":
        import ida_expr

        # exec_idc_script stays silent about compile errors: compile first
        err = ida_expr.compile_idc_file(path) or ida_expr.exec_idc_script(None, path, "main", None, 0)
        if err:
            raise IcliError(Exit.SCRIPT, f"{path}: IDC script failed: {err}", "SCRIPT")
        return [{"_t": "load", "kind": "idc", "path": path}]
    if kind in ("names", "map"):
        out = []
        for r in records or []:
            out.append(edits.change(ctx, "name", r["ea"], None, r["name"], force=True, record={"name": r["name"]}))
        return out
    if kind == "coverage":
        from .. import coverage

        import ida_nalt

        base = ida_nalt.get_imagebase()
        counts: dict[int, int] = {}
        for r in records or []:
            ea = int(r["ea"]) if r.get("ea") is not None else base + int(r["rva"])
            counts[ea] = counts.get(ea, 0) + int(r.get("hits", 1))
        n = coverage.add(counts)
        return [{"_t": "load", "kind": "coverage", "blocks": len(counts), "stored": n}]
    if kind in ("binary", "snapshot"):
        if at is None:
            raise IcliError(Exit.USAGE, f"load {kind} needs --at ADDR", "USAGE")
        from .analysis import create_segment

        data = Path(path).read_bytes()
        seg_name = name or Path(path).name.replace(".", "_")[:32]
        if ida_bytes.get_flags(at) and ida_bytes.is_loaded(at) and kind == "binary":
            raise IcliError(Exit.CONFLICT, f"{at:#x} is already loaded", "CONFLICT")
        if kind == "snapshot" and ida_bytes.is_loaded(at):
            ida_bytes.put_bytes(at, data)  # memory dump over existing segments
        else:
            create_segment(seg_name, at, at + len(data), "DATA", "rwx")
            ida_bytes.put_bytes(at, data)
        ida_auto.plan_range(at, at + len(data))
        from .. import lifecycle

        lifecycle.mark(analyzed=None)
        return [{"_t": "load", "kind": kind, "ea": A(at), "end": A(at + len(data)), "size": len(data)}]
    raise IcliError(Exit.USAGE, f"unknown load kind {kind!r}", "USAGE")
