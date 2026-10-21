"""Selector evaluation inside IDA.

A selection is an ordered, duplicate-free list of :class:`Item` keyed by
``item.key``.  See :mod:`icli.lang.selector` for the AST.
"""

from __future__ import annotations

from typing import Any, Iterable

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_segment
import ida_xref

from ..errors import Exit, IcliError
from ..lang import expr as pexpr
from ..lang import selector as psel
from . import addresses
from .context import Ctx
from .kinds import KINDS, Item, Kind, compile_pattern

BADADDR = ida_idaapi.BADADDR


class Selection:
    def __init__(self, items: Iterable[Item] = (), kind: Kind | None = None) -> None:
        self.items: dict[Any, Item] = {}
        self.kind = kind
        for it in items:
            self.add(it)

    def add(self, it: Item) -> None:
        self.items.setdefault(it.key, it)

    def __iter__(self):
        return iter(self.items.values())

    def __len__(self) -> int:
        return len(self.items)

    def eas(self) -> list[int]:
        return [it.ea for it in self if isinstance(it.ea, int)]

    def is_ranges(self) -> bool:
        return bool(self.items) and all(it.end is not None and it.kind.name in ("range", "segment")
                                        for it in self)


def kind(name: str) -> Kind:
    return KINDS[name]


# -- entry points ----------------------------------------------------------------


def evaluate(ctx: Ctx, nodes: list[dict] | dict) -> Selection:
    """Evaluate one or more selector ASTs; several selectors are a union."""
    if isinstance(nodes, dict):
        nodes = [nodes]
    out = Selection()
    for node in nodes:
        sel = _eval(ctx, node)
        if out.kind is None:
            out.kind = sel.kind
        for it in sel:
            out.add(it)
    return out


def evaluate_or_all(ctx: Ctx, nodes: list[dict] | None, default_kind: str) -> Selection:
    if not nodes:
        k = kind(default_kind)
        return Selection(k.all(ctx), k)
    return evaluate(ctx, nodes)


def functions_of(ctx: Ctx, sel: Selection) -> Selection:
    """The functions containing the selected items (all chunks)."""
    fk = kind("function")
    out = Selection(kind=fk)
    for it in sel:
        if it.kind is fk:
            out.add(it)
            continue
        if it.end is not None and it.kind.name in ("range", "segment"):
            for fi in fk.all(ctx):
                if it.ea <= fi.ea < it.end:
                    out.add(fi)
            continue
        if isinstance(it.ea, int):
            fi = fk.at(ctx, it.ea)
            if fi is not None:
                out.add(fi)
    return out


def addresses_of(sel: Selection) -> list[int]:
    return [it.ea for it in sel if isinstance(it.ea, int)]


# -- evaluation ------------------------------------------------------------------


def _eval(ctx: Ctx, node: dict) -> Selection:
    op = node["op"]
    fn = _OPS.get(op)
    if fn is None:
        raise IcliError(Exit.USAGE, f"selector operator {op!r} is not valid here", "USAGE")
    return fn(ctx, node)


def _addr(ctx: Ctx, node: dict) -> Selection:
    eas = addresses.evaluate(node["expr"])
    if not eas:
        raise IcliError(Exit.EMPTY_SELECTION,
                        f"no such name or address: {addresses.describe(node['expr'])}", "NOMATCH")
    k = kind("address")
    return Selection((Item(k, ea) for ea in eas), k)


def _range(ctx: Ctx, node: dict) -> Selection:
    starts = addresses.evaluate(node["start"])
    if len(starts) != 1:
        raise IcliError(Exit.USAGE, "range start must denote one address", "USAGE")
    start = starts[0]
    if node.get("size") is not None:
        size = addresses.evaluate(node["size"])[0]
        end = start + size
    elif node.get("end") is not None:
        end = addresses.evaluate(node["end"])[0]
    else:
        seg = ida_segment.getseg(start)
        if seg is None:
            raise IcliError(Exit.EMPTY_SELECTION, f"{start:#x} is not in a segment", "NOMATCH")
        end = seg.end_ea
    if end <= start:
        raise IcliError(Exit.USAGE, f"empty range {start:#x}..{end:#x}", "USAGE")
    k = kind("range")
    return Selection([Item(k, start, end=end, key=("range", start, end))], k)


def _typed(ctx: Ctx, node: dict) -> Selection:
    t = node["type"]
    if t == "bytes":
        return _bytes(ctx, node)
    if t == "diff":
        return _diff(ctx, node)
    kname = {"func": "function", "seg": "segment", "name": "name", "str": "string", "imp": "import",
             "exp": "export", "type": "type", "tag": "tag"}[t]
    k = kind(kname)
    match = compile_pattern(node["pattern"], node["regex"], node.get("flags", ""))
    out = Selection(kind=k)
    if t == "imp":
        mmatch = compile_pattern(node.get("module", "*"), node.get("module_regex", False),
                                 node.get("flags", ""))
        for it in k.all(ctx):
            module = k.get(it, "module", ctx) or ""
            if (mmatch(module) or mmatch(module.rsplit(".", 1)[0])) and any(
                    match(n) for n in k.names(it, ctx)):
                out.add(it)
        return out
    if t == "str":
        for it in k.all(ctx):
            if match(k.get(it, "value", ctx) or ""):
                out.add(it)
        return out
    if t == "tag":
        for it in k.all(ctx):
            if match(k.get(it, "tag", ctx) or ""):
                out.add(it)
        return out
    for it in k.all(ctx):
        if any(match(n) for n in k.names(it, ctx)):
            out.add(it)
    return out


def _bytes(ctx: Ctx, node: dict) -> Selection:
    from .search import find_bytes

    k = kind("address")
    return Selection((Item(k, ea) for ea in find_bytes(node["pattern"])), k)


def _diff(ctx: Ctx, node: dict) -> Selection:
    k = kind("record")
    match = compile_pattern(node["pattern"], node["regex"], node.get("flags", ""))
    out = Selection(kind=k)
    for rec in ctx.prev:
        if rec.get("_t") == "diff" and match(str(rec.get("diff", ""))):
            out.add(_record_item(rec))
    return out


def _class(ctx: Ctx, node: dict) -> Selection:
    name = node["name"]
    if name == "entry":
        k = kind("entry")
        return Selection(k.all(ctx), k)
    if name == "patched":
        k = kind("patch")
        return Selection(k.all(ctx), k)
    if name == "problem":
        k = kind("problem")
        return Selection(k.all(ctx), k)
    fk = kind("function")
    field = {"lib": "lib", "thunk": "thunk", "noret": "noret", "dummy": "dummy", "named": "named"}.get(name)
    out = Selection(kind=fk)
    for it in fk.all(ctx):
        if name == "lumina":
            if fk.get(it, "lumina", ctx) != "none":
                out.add(it)
        elif fk.get(it, field, ctx):
            out.add(it)
    return out


def _func_at(ctx: Ctx, node: dict) -> Selection:
    fk = kind("function")
    out = Selection(kind=fk)
    for ea in addresses.evaluate(node["addr"]):
        it = fk.at(ctx, ea)
        if it is None:
            raise IcliError(Exit.EMPTY_SELECTION, f"no function contains {ea:#x}", "NOMATCH")
        out.add(it)
    return out


def _record_item(rec: dict) -> Item:
    from ..lang.values import parse_address_number

    ea = None
    for key in ("ea", "start", "from", "to"):
        v = rec.get(key)
        if isinstance(v, int):
            ea = v
        elif isinstance(v, str) and v:
            ea = parse_address_number(v)
            if ea is None:
                try:
                    found = addresses.evaluate(psel.parse_addrexpr(v))
                    ea = found[0] if found else None
                except IcliError:
                    ea = None
        if ea is not None:
            break
    end = None
    if isinstance(rec.get("end"), str):
        end = parse_address_number(rec["end"])
    k = kind("record")
    key = ea if ea is not None else ("record", id(rec))
    return Item(k, ea, end=end, key=key, record=rec)


def _items(ctx: Ctx, node: dict) -> Selection:
    k = kind("record")
    return Selection((_record_item(r) for r in node["items"]), k)


def _prev(ctx: Ctx, node: dict) -> Selection:
    k = kind("record")
    return Selection((_record_item(r) for r in ctx.prev if r.get("_t") != "diag"), k)


def _pred(ctx: Ctx, node: dict) -> Selection:
    base = _eval(ctx, node["arg"])
    tree = pexpr.parse(node["expr"])
    out = Selection(kind=base.kind)
    for it in base:
        if pexpr.test(tree, lambda name, it=it: it.kind.get(it, name, ctx)):
            out.add(it)
    return out


def _union(ctx: Ctx, node: dict) -> Selection:
    out = Selection()
    for a in node["args"]:
        s = _eval(ctx, a)
        out.kind = out.kind or s.kind
        for it in s:
            out.add(it)
    return out


def _contains(ranges: Selection, it: Item) -> bool:
    return isinstance(it.ea, int) and any(r.ea <= it.ea < r.end for r in ranges)


def _inter(ctx: Ctx, node: dict) -> Selection:
    sels = [_eval(ctx, a) for a in node["args"]]
    out = sels[0]
    for s in sels[1:]:
        if s.is_ranges() and not out.is_ranges():
            out = Selection((it for it in out if _contains(s, it)), out.kind)
        elif out.is_ranges() and not s.is_ranges():
            out = Selection((it for it in s if _contains(out, it)), s.kind)
        else:
            out = Selection((it for it in out if it.key in s.items or (
                isinstance(it.ea, int) and it.ea in {x.ea for x in s})), out.kind)
    return out


def _diff_op(ctx: Ctx, node: dict) -> Selection:
    sels = [_eval(ctx, a) for a in node["args"]]
    out = sels[0]
    for s in sels[1:]:
        if s.is_ranges() and not out.is_ranges():
            out = Selection((it for it in out if not _contains(s, it)), out.kind)
        else:
            eas = {x.ea for x in s}
            out = Selection((it for it in out if it.key not in s.items and it.ea not in eas), out.kind)
    return out


def _kind_of_node(node: dict) -> str | None:
    op = node["op"]
    if op == "typed":
        return {"func": "function", "seg": "segment", "name": "name", "str": "string", "imp": "import",
                "exp": "export", "type": "type", "tag": "tag"}.get(node["type"])
    if op == "class":
        return {"entry": "entry", "patched": "patch", "problem": "problem"}.get(node["name"], "function")
    if op in ("func_at",):
        return "function"
    if op == "graph":
        return "block" if node["name"] == "blocks" else (
            "function" if node["name"] in ("callers", "callees", "func", "uses_type") else "address")
    if op in ("pred", "not"):
        return _kind_of_node(node["arg"])
    if op in ("union", "inter", "diff"):
        return _kind_of_node(node["args"][0])
    return None


def _not(ctx: Ctx, node: dict) -> Selection:
    inner = _eval(ctx, node["arg"])
    kname = (inner.kind.name if inner.kind and inner.kind.name not in ("address", "record", "range")
             else None) or _kind_of_node(node["arg"])
    if kname is None or kname in ("address", "range", "record"):
        raise IcliError(Exit.USAGE, "complement (!) needs a selector of a kind (functions, strings, ...)",
                        "USAGE")
    k = kind(kname)
    return Selection((it for it in k.all(ctx) if it.key not in inner.items), k)


# -- graph operators ----------------------------------------------------------------


def _targets(ctx: Ctx, sel: Selection) -> list[int]:
    """Addresses that callers()/xrefs() look for references to."""
    return [it.ea for it in sel if isinstance(it.ea, int)]


def _graph(ctx: Ctx, node: dict) -> Selection:
    name = node["name"]
    fk = kind("function")
    if name == "uses_type":
        return _uses_type(ctx, node)
    base = _eval(ctx, node["arg"])
    if name == "func":
        return functions_of(ctx, base)
    if name == "blocks":
        bk = kind("block")
        out = Selection(kind=bk)
        for fi in functions_of(ctx, base):
            for b in bk.of_function(fi.obj):  # type: ignore[attr-defined]
                out.add(b)
        return out
    if name in ("callers", "callees"):
        from .kinds.functions import callees as fcallees
        from .kinds.functions import callers as fcallers

        depth = None if node.get("closure") else (node.get("depth") or 1)
        frontier = _targets(ctx, base) if name == "callers" else [it.ea for it in functions_of(ctx, base)]
        seen: dict[int, None] = {}
        level = 0
        while frontier and (depth is None or level < depth):
            level += 1
            nxt: list[int] = []
            for ea in frontier:
                if name == "callers":
                    found = fcallers(ea)
                else:
                    f = ida_funcs.get_func(ea)
                    found = fcallees(f) if f is not None else []
                for x in found:
                    if x not in seen:
                        seen[x] = None
                        nxt.append(x)
            frontier = nxt
        out = Selection(kind=fk)
        ak = kind("address")
        for ea in seen:
            fi = fk.at(ctx, ea)
            if fi is not None and fi.ea == ea:
                out.add(fi)
            else:
                out.add(Item(ak, ea))
        return out
    ak = kind("address")
    out = Selection(kind=ak)
    if name in ("xrefs", "drefs", "crefs"):
        for ea in _targets(ctx, base):
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(ea, ida_xref.XREF_NOFLOW)
            while ok:
                if (name == "xrefs" or (name == "crefs") == bool(xb.iscode)):
                    out.add(Item(ak, xb.frm))
                ok = xb.next_to()
        return out
    if name == "refs":
        from .kinds.base import iter_heads

        for it in base:
            if not isinstance(it.ea, int):
                continue
            if it.kind is fk:
                from .kinds.functions import chunks

                spans = chunks(it.obj)
            elif it.end is not None:
                spans = [(it.ea, it.end)]
            else:
                spans = [(it.ea, ida_bytes.get_item_end(it.ea))]
            for s, e in spans:
                for h in iter_heads(s, e):
                    xb = ida_xref.xrefblk_t()
                    ok = xb.first_from(h, ida_xref.XREF_NOFLOW)
                    while ok:
                        out.add(Item(ak, xb.to))
                        ok = xb.next_from()
        return out
    raise IcliError(Exit.USAGE, f"unknown graph operator {name}", "USAGE")


def _uses_type(ctx: Ctx, node: dict) -> Selection:
    from . import decomp, typesupport

    match = compile_pattern(node["pattern"], node["regex"], node.get("flags", ""))
    fk = kind("function")
    out = Selection(kind=fk)
    for it in fk.all(ctx):
        names = typesupport.type_names_in(typesupport.prototype(it.ea) or "")
        if any(match(n) for n in names):
            out.add(it)
            continue
        if decomp.available() and decomp.has_cached(it.ea):
            r = decomp.decompile(it.ea)
            if r.ok and any(match(n) for lv in r.cfunc.get_lvars()
                            for n in typesupport.type_names_in(str(lv.type()))):
                out.add(it)
    return out


def _stdin(ctx: Ctx, node: dict) -> Selection:
    raise IcliError(Exit.USAGE, "'-' (standard input) cannot be used here", "USAGE")


def _file(ctx: Ctx, node: dict) -> Selection:
    raise IcliError(Exit.USAGE, f"@{node['path']}: selector files must be expanded by the client", "USAGE")


_OPS = {
    "addr": _addr, "range": _range, "typed": _typed, "class": _class, "func_at": _func_at,
    "items": _items, "prev": _prev, "pred": _pred, "union": _union, "inter": _inter,
    "diff": _diff_op, "not": _not, "graph": _graph, "stdin": _stdin, "file": _file,
}
