"""decompile (and the shared pseudocode helpers used by search/export)."""

from __future__ import annotations

import re
from typing import Any

import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines

from ...errors import Exit, IcliError
from .. import decomp, select, typesupport
from ..context import A, Ctx
from ..kinds import KINDS
from ..rpc import op
from .common import selection

BADADDR = ida_idaapi.BADADDR
_ANCHOR = re.compile(re.escape(ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR) + "([0-9A-Fa-f]{16})")


def line_addresses(cf: Any) -> list[list[int]]:
    """For each pseudocode line, the addresses of the ctree items on it."""
    out: list[list[int]] = []
    items = cf.treeitems
    n = len(items)
    for sl in cf.get_pseudocode():
        eas: dict[int, None] = {}
        for m in _ANCHOR.finditer(sl.line):
            value = int(m.group(1), 16)
            if (value & ida_hexrays.ANCHOR_MASK) != ida_hexrays.ANCHOR_CITEM:
                continue
            index = value & ida_hexrays.ANCHOR_INDEX
            if index < n:
                ea = items[index].ea
                if ea != BADADDR:
                    eas.setdefault(ea, None)
        out.append(list(eas))
    return out


def lines_for(cf: Any, ea: int) -> list[int]:
    """Line indices that cover ``ea`` (exact item match, else the nearest
    preceding item within the function)."""
    mapping = line_addresses(cf)
    hits = [i for i, eas in enumerate(mapping) if ea in eas]
    if hits:
        return hits
    best, best_ea = None, -1
    for i, eas in enumerate(mapping):
        for x in eas:
            if best_ea < x <= ea:
                best, best_ea = i, x
    return [best] if best is not None else []


def ctree(cf: Any) -> dict:
    """The ctree as nested JSON: node (op name), ea, type, children."""
    nodes: dict[int, dict] = {}
    root: dict = {}

    class V(ida_hexrays.ctree_parentee_t):
        def __init__(self) -> None:
            super().__init__(False)

        def _add(self, item: Any, is_expr: bool) -> int:
            node = {"node": ida_hexrays.get_ctype_name(item.op), "ea": A(item.ea) if item.ea != BADADDR else None,
                    "children": []}
            if is_expr:
                e = item.cexpr if hasattr(item, "cexpr") else item
                try:
                    node["type"] = str(e.type)
                except Exception:
                    pass
                if e.op == ida_hexrays.cot_num:
                    node["value"] = int(e.numval())
                elif e.op == ida_hexrays.cot_obj:
                    node["obj"] = A(e.obj_ea)
                elif e.op == ida_hexrays.cot_var:
                    node["var"] = cf.get_lvars()[e.v.idx].name
                elif e.op == ida_hexrays.cot_str:
                    node["string"] = e.string
                elif e.op == ida_hexrays.cot_helper:
                    node["helper"] = e.helper
            nodes[item.obj_id] = node
            parent = self.parents.back() if self.parents.size() else None
            if parent is not None and parent.obj_id in nodes:
                nodes[parent.obj_id]["children"].append(node)
            elif not root:
                root.update(node)
                nodes[item.obj_id] = root
            return 0

        def visit_insn(self, i: Any) -> int:  # noqa: N802 - SDK callback
            return self._add(i, False)

        def visit_expr(self, e: Any) -> int:  # noqa: N802 - SDK callback
            return self._add(e, True)

    V().apply_to(cf.body, None)
    return root


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def referenced_types(text: str) -> list[tuple[str, str]]:
    """(name, definition) of local types referenced by ``text``, dependencies first."""
    local = {name: tif for _, name, tif in typesupport.local_types()}
    defs: dict[str, str] = {}
    order: list[str] = []

    def visit(name: str, depth: int = 0) -> None:
        if name in defs or name not in local or depth > 64:
            return
        d = typesupport.type_definition(local[name], name)
        defs[name] = d
        for dep in _IDENT.findall(d):
            if dep != name:
                visit(dep, depth + 1)
        order.append(name)

    for ident in dict.fromkeys(_IDENT.findall(text)):
        visit(ident)
    return [(n, defs[n]) for n in order]


def decompile_record(ctx: Ctx, ea: int, *, fresh: bool = False, line_map: bool = False,
                     with_ctree: bool = False) -> dict:
    r = decomp.decompile(ea, fresh=fresh)
    name = ida_funcs.get_func_name(r.ea) or f"sub_{r.ea:x}"
    rec: dict[str, Any] = {"_t": "pseudocode", "ea": A(r.ea), "name": name}
    if not r.ok:
        rec.update({"status": "failed", "hexrays_err": r.err, "hexrays_msg": r.message,
                    "err_ea": A(r.err_ea) if r.err_ea is not None else None, "pseudocode": None})
        return rec
    text = r.text
    rec.update({"status": "ok", "hexrays_err": 0, "pseudocode": text})
    if ctx.opts.strict and ("JUMPOUT" in text or "__asm" in text):
        ctx.warn("UNCLEAN", f"{name}: pseudocode contains JUMPOUT or __asm")
    if line_map:
        mapping = line_addresses(r.cfunc)
        rec["lines"] = [{"line": i + 1, "text": t, "addresses": [A(x) for x in eas]}
                        for i, (t, eas) in enumerate(zip(text.split("\n"), mapping))]
        rec["lvars"] = [{"name": lv.name, "type": str(lv.type()), "storage": decomp.lvar_storage(lv),
                         "arg": bool(lv.is_arg_var)} for lv in r.cfunc.get_lvars()]
    if with_ctree:
        rec["ctree"] = ctree(r.cfunc)
    return rec


@op("decompile")
def decompile(ctx: Ctx, selectors: list[dict] | None = None, all: bool = False, with_types: bool = False,
              at_line: bool = False, ctree: bool = False, line_map: bool = False, fresh: bool = False,
              hexrays_directives: list[str] | None = None) -> Any:
    decomp.require()
    for d in hexrays_directives or []:
        if not ida_hexrays.change_hexrays_config(d):
            raise IcliError(Exit.USAGE, f"--hexrays-option: rejected {d!r}", "USAGE")
    if fresh:
        decomp.reset()
    fk = KINDS["function"]
    if all:
        import ida_segment

        def decompilable(it: Any) -> bool:
            seg = ida_segment.getseg(it.ea)
            return not fk.get(it, "lib", ctx) and (seg is None or seg.type not in (
                ida_segment.SEG_XTRN, ida_segment.SEG_IMP))

        funcs = [it for it in fk.all(ctx) if decompilable(it)]
        if selectors:
            keep = {it.ea for it in select.functions_of(ctx, selection(ctx, selectors, required=False))}
            funcs = [f for f in funcs if f.ea in keep]
        sel_items = None
    else:
        sel_items = selection(ctx, selectors)
        funcs = list(select.functions_of(ctx, sel_items))
        if not funcs:
            raise IcliError(Exit.EMPTY_SELECTION, "selection contains no function", "NOMATCH")
    if at_line:
        return _at_line(ctx, sel_items, fresh)
    out = []
    failed = 0
    for fi in funcs:
        rec = decompile_record(ctx, fi.ea, fresh=fresh, line_map=line_map, with_ctree=ctree)
        if rec["status"] == "failed":
            failed += 1
        out.append(rec)
    if with_types:
        text = "\n".join(r["pseudocode"] or "" for r in out)
        decls = referenced_types(text)
        if decls:
            header = "\n\n".join(d for _, d in decls) + "\n"
            out.insert(0, {"_t": "types", "names": [n for n, _ in decls], "pseudocode": header})
    if failed:
        if all or len(funcs) > 1:
            ctx.set_status(Exit.PARTIAL)
        else:
            r = out[-1]
            raise IcliError(Exit.DECOMPILE, f"{r['name']}: decompilation failed at "
                            f"{r['err_ea'] or r['ea']}: {r['hexrays_msg']}", "HEXRAYS")
    return out


def _at_line(ctx: Ctx, sel: Any, fresh: bool) -> list[dict]:
    out = []
    for it in sel:
        if not isinstance(it.ea, int):
            continue
        r = decomp.decompile(it.ea, fresh=fresh)
        name = ida_funcs.get_func_name(r.ea) if ida_funcs.get_func(it.ea) else None
        if not r.ok:
            out.append({"_t": "pseudocode_line", "ea": A(it.ea), "func": name, "line": None, "text": None,
                        "status": "failed", "hexrays_err": r.err})
            ctx.set_status(Exit.PARTIAL)
            continue
        lines = r.text.split("\n")
        for idx in lines_for(r.cfunc, it.ea):
            out.append({"_t": "pseudocode_line", "ea": A(it.ea), "func": name, "line": idx + 1,
                        "text": lines[idx].strip(), "status": "ok"})
    return out
