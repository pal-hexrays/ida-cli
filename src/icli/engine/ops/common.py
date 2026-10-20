"""Helpers shared by engine operations."""

from __future__ import annotations

from typing import Any, Iterable

import ida_bytes

from ...errors import Exit, IdaxError
from ...lang import expr as pexpr
from .. import select
from ..context import Ctx
from ..kinds import KINDS, Item, Kind, compile_pattern


def selection(ctx: Ctx, selectors: list[dict] | None, *, required: bool = True) -> select.Selection:
    """Evaluate the command's selectors.  An empty result is status 5 when
    the command requires a selection, a warning otherwise."""
    if not selectors:
        if required:
            raise IdaxError(Exit.USAGE, "this command needs at least one selector", "USAGE")
        return select.Selection()
    sel = select.evaluate(ctx, selectors)
    if not len(sel):
        if required:
            raise IdaxError(Exit.EMPTY_SELECTION, "selector matched nothing", "NOMATCH")
        ctx.warn("NOMATCH", "selector matched nothing")
    return sel


def spans(sel: select.Selection) -> list[tuple[int, int]]:
    from ..kinds.functions import chunks

    out: list[tuple[int, int]] = []
    for it in sel:
        if not isinstance(it.ea, int):
            continue
        if it.kind.name == "function":
            out.extend(chunks(it.obj))
        elif it.end is not None:
            out.append((it.ea, it.end))
        else:
            out.append((it.ea, max(ida_bytes.get_item_end(it.ea), it.ea + 1)))
    return out


def within(ea: Any, sp: list[tuple[int, int]]) -> bool:
    return isinstance(ea, int) and any(s <= ea < e for s, e in sp)


def restrict(ctx: Ctx, kind: Kind, sel: select.Selection) -> Iterable[Item]:
    """Items of ``kind`` restricted to a selection (``list kind sel...``)."""
    if sel.kind is kind or all(it.kind is kind for it in sel):
        return list(sel)
    name = kind.name
    if name == "function":
        return list(select.functions_of(ctx, sel))
    if name == "block":
        return [b for f in select.functions_of(ctx, sel) for b in kind.of_function(f.obj)]  # type: ignore
    if name == "lvar":
        return [lv for f in select.functions_of(ctx, sel) for lv in kind.of_function(ctx, f.ea)]  # type: ignore
    if name == "xref":
        from ..kinds.base import iter_heads

        out: list[Item] = []
        for s, e in spans(sel):
            for h in iter_heads(s, e):
                out.extend(kind.from_ea(h))  # type: ignore[attr-defined]
        for it in sel:
            if it.kind.name in ("address", "record", "string", "name", "import", "export", "entry"):
                out.extend(kind.to_ea(it.ea))  # type: ignore[attr-defined]
        return out
    if name in ("type", "til", "sig"):
        names = {n for it in sel for n in it.kind.names(it, ctx)}
        return [it for it in kind.all(ctx) if any(n in names for n in kind.names(it, ctx))]
    sp = spans(sel)
    return [it for it in kind.all(ctx) if within(it.ea, sp)]


def filter_items(ctx: Ctx, items: Iterable[Item], *, where: str | None = None, match: str | None = None,
                 regex: str | None = None) -> list[Item]:
    tree = pexpr.parse(where) if where else None
    mglob = compile_pattern(match, False) if match else None
    mre = compile_pattern(regex, True) if regex else None
    out = []
    for it in items:
        if mglob and not any(mglob(n) for n in it.kind.names(it, ctx)):
            continue
        if mre and not any(mre(n) for n in it.kind.names(it, ctx)):
            continue
        if tree is not None and not pexpr.test(tree, lambda name, it=it: it.kind.get(it, name, ctx)):
            continue
        out.append(it)
    return out


def sort_items(ctx: Ctx, items: list[Item], sort: str | None) -> list[Item]:
    if not sort:
        return items
    field, _, order = sort.partition(":")
    if order not in ("", "asc", "desc"):
        raise IdaxError(Exit.USAGE, f"bad sort order {order!r} (asc or desc)", "USAGE")
    desc = order == "desc"

    def key(it: Item) -> tuple:
        v = it.kind.get(it, field, ctx)
        if v is None:
            return (1, 0, "")
        if isinstance(v, bool):
            return (0, int(v), "")
        if isinstance(v, (int, float)):
            return (0, v, "")
        return (0, 0, str(v))

    present = [it for it in items if it.kind.get(it, field, ctx) is not None]
    missing = [it for it in items if it.kind.get(it, field, ctx) is None]
    return sorted(present, key=key, reverse=desc) + missing


def records(ctx: Ctx, items: list[Item], fields: list[str] | None = None) -> list[dict]:
    fields = fields or ctx.opts.fields
    n = len(items)
    out = []
    for i, it in enumerate(items):
        rec = it.kind.to_record(it, ctx, fields)
        if fields:
            if "index" in fields:
                rec["index"] = i
            if "count" in fields:
                rec["count"] = n
        out.append(rec)
    return out


def kind_for_list(name: str) -> Kind:
    k = KINDS.get(name)
    valid = ["functions", "names", "strings", "imports", "exports", "entries", "segments", "xrefs", "types",
             "tils", "sigs", "comments", "bookmarks", "tags", "problems", "fixups", "blocks", "patches",
             "lvars", "switches"]
    if k is None or name not in valid:
        raise IdaxError(Exit.USAGE, f"unknown kind {name!r}; one of: {', '.join(valid)}", "USAGE")
    return k
