"""show and disasm."""

from __future__ import annotations

from typing import Any

import ida_bytes
import ida_frame
import ida_funcs
import ida_gdl
import ida_name
import ida_typeinf

from ...errors import Exit, IcliError
from ...lang.graph import render
from .. import decomp, listing, typesupport
from ..context import A, Ctx
from ..kinds import KINDS
from ..kinds.annotations import comments_at
from ..kinds.base import item_flags, iter_heads
from ..kinds.functions import chunks
from ..rpc import op
from .common import selection


def _xrefs(ea: int, to: bool) -> list[dict]:
    xk = KINDS["xref"]
    items = xk.to_ea(ea) if to else xk.from_ea(ea)  # type: ignore[attr-defined]
    return [{"from": A(i.obj["from"]), "to": A(i.obj["to"]), "type": i.obj["type"]} for i in items]


def _frame(f: Any) -> list[dict]:
    """Stack frame members, offsets from the frame start."""
    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    if not ida_frame.get_func_frame(tif, f) or not tif.get_udt_details(udt):
        return []
    return [{"offset": m.offset // 8, "name": m.name, "size": m.size // 8, "type": str(m.type)} for m in udt]


def show_record(ctx: Ctx, ea: int) -> dict:
    f = ida_bytes.get_flags(ea)
    head = ida_bytes.get_item_head(ea)
    func = ida_funcs.get_func(ea)
    ak = KINDS["address"]
    ai = ak.at(ctx, ea)
    rec: dict[str, Any] = {
        "_t": "item",
        "ea": A(ea),
        "head": A(head) if head != ea else None,
        "segment": ak.get(ai, "segment", ctx),
        "item": ak.get(ai, "item", ctx),
        "size": ida_bytes.get_item_size(ea),
        "flags": item_flags(ea),
        "name": ida_name.get_name(ea) or None,
        "demangled": ida_name.get_demangled_name(ea, ida_name.MNG_SHORT_FORM, 0) or None,
        "func": ida_funcs.get_func_name(func.start_ea) if func else None,
        "func_ea": A(func.start_ea) if func else None,
        "comments": comments_at(ea),
        "disasm": listing.instruction_text(ea, comments=True) if ida_bytes.is_head(f) else None,
        "bytes": listing.item_bytes(ea, 32).hex(),
        "type": typesupport.type_at(ea),
        "user_type": typesupport.is_user_type(ea),
        "xrefs_to": _xrefs(ea, True),
        "xrefs_from": _xrefs(ea, False),
    }
    if ida_bytes.is_code(f):
        rec["mnem"] = listing.mnemonic(ea)
        rec["operands"] = listing.operands(ea)
    from .. import tags

    rec["tags"] = tags.get(ea)
    if func is not None and func.start_ea == ea:
        fk = KINDS["function"]
        fi = fk.at(ctx, ea)
        rec["function"] = {
            "prototype": typesupport.prototype(ea),
            "end": A(func.end_ea),
            "size": fk.get(fi, "size", ctx),
            "flags": fk.get(fi, "flags", ctx),
            "chunks": [{"start": A(s), "end": A(e)} for s, e in chunks(func)],
            "frame_size": int(func.frsize),
            "frame": _frame(func),
            "callers": fk.get(fi, "caller_names", ctx),
            "callees": fk.get(fi, "callee_names", ctx),
        }
    return rec


@op("show")
def show(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in sel:
        if isinstance(it.ea, int):
            out.append(show_record(ctx, it.ea))
        else:
            out.append(it.kind.to_record(it, ctx, list(it.kind.fields)))
    return out


def _spans_for(ctx: Ctx, sel: Any) -> list[tuple[int, int, str | None]]:
    """Function selectors print whole functions (chunks included)."""
    out = []
    fk = KINDS["function"]
    for it in sel:
        if not isinstance(it.ea, int):
            continue
        f = ida_funcs.get_func(it.ea)
        if it.kind is fk or (it.kind.name in ("address", "record") and f is not None and f.start_ea == it.ea):
            for s, e in chunks(f):
                out.append((s, e, ida_funcs.get_func_name(f.start_ea)))
        elif it.end is not None:
            out.append((it.ea, it.end, None))
        else:
            out.append((it.ea, ida_bytes.get_item_end(it.ea), None))
    return out


@op("disasm")
def disasm(ctx: Ctx, selectors: list[dict], bytes: int | None = None, xrefs: bool = True,
           comments: bool = True, prefix: bool = True, syntax: str | None = None,
           graph: str | None = None, microcode: str | None = None) -> Any:
    sel = selection(ctx, selectors)
    if microcode:
        out = []
        for fi in {it.ea: it for it in _functions(ctx, sel)}.values():
            text = decomp.microcode(fi.ea, microcode)
            out.append({"_t": "microcode", "ea": A(fi.ea), "name": ida_funcs.get_func_name(fi.ea),
                        "maturity": microcode, "text": text})
        return out
    if graph:
        return _cfg_graphs(ctx, sel, graph)
    out = []
    with listing.syntax(syntax):
        for start, end, _ in _spans_for(ctx, sel):
            for ea in iter_heads(start, end):
                lines = listing.item_lines(ea, comments=comments, xrefs=xrefs)
                raw = listing.item_bytes(ea)
                pre = listing.prefix(ea, ctx.opts.addr) if prefix else ""
                bhex = ""
                if bytes is not None:
                    n = bytes or 8
                    bhex = f"{raw[:n].hex(' ').upper():<{n * 3 - 1}}"
                text = listing.instruction_text(ea, comments=comments)
                rendered = listing.render_lines(lines, pre, bhex)
                rec = {
                    "_t": "insn" if ida_bytes.is_code(ida_bytes.get_flags(ea)) else "item",
                    "ea": A(ea),
                    "size": len(raw),
                    "bytes": raw.hex(),
                    "mnem": listing.mnemonic(ea) if ida_bytes.is_code(ida_bytes.get_flags(ea)) else None,
                    "operands": listing.operands(ea) if ida_bytes.is_code(ida_bytes.get_flags(ea)) else [],
                    "text": text,
                    "line": "\n".join(rendered),
                }
                out.append(rec)
    return out


def _functions(ctx: Ctx, sel: Any) -> list:
    from .. import select

    fs = list(select.functions_of(ctx, sel))
    if not fs:
        raise IcliError(Exit.EMPTY_SELECTION, "selection contains no function", "NOMATCH")
    return fs


def _cfg_graphs(ctx: Ctx, sel: Any, fmt: str) -> Any:
    if fmt not in ("dot", "gdl", "json"):
        raise IcliError(Exit.USAGE, f"--graph {fmt}: one of dot, gdl, json", "USAGE")
    out = []
    for fi in _functions(ctx, sel):
        fc = ida_gdl.FlowChart(fi.obj, flags=ida_gdl.FC_PREDS)
        nodes, edges = [], []
        for b in fc:
            label = "\n".join(f"{ea:#x}: {listing.instruction_text(ea)}" for ea in iter_heads(b.start_ea, b.end_ea))
            nodes.append({"id": f"{b.start_ea:#x}", "label": label, "start": A(b.start_ea), "end": A(b.end_ea)})
            for s in b.succs():
                edges.append({"src": f"{b.start_ea:#x}", "dst": f"{s.start_ea:#x}"})
        name = ida_funcs.get_func_name(fi.ea)
        if fmt == "json":
            out.append({"_t": "graph", "name": name, "ea": A(fi.ea), "nodes": nodes, "edges": edges})
        else:
            ctx.raw.append(render(nodes, edges, fmt, name))
    return out
