"""list, resolve, show."""

from __future__ import annotations

from typing import Any

from ...errors import Exit
from .. import select
from ..context import A, Ctx
from ..rpc import op
from .common import filter_items, kind_for_list, records, restrict, sort_items


@op("list")
def list_(ctx: Ctx, kind: str, selectors: list[dict] | None = None, where: str | None = None,
          match: str | None = None, regex: str | None = None, sort: str | None = None,
          limit: int | None = None, count: bool = False) -> Any:
    k = kind_for_list(kind)
    if selectors:
        sel = select.evaluate(ctx, selectors)
        if not len(sel):
            ctx.warn("NOMATCH", "selector matched nothing")
        items = list(restrict(ctx, k, sel))
    else:
        items = list(k.all(ctx))
    items = filter_items(ctx, items, where=where, match=match, regex=regex)
    items = sort_items(ctx, items, sort)
    if limit is not None:
        items = items[: max(limit, 0)]
    if not items and (where or match or regex):
        ctx.set_status(Exit.NEGATIVE)
    if count:
        return {"_t": "count", "kind": k.plural, "count": len(items)}
    return records(ctx, items)


@op("resolve")
def resolve(ctx: Ctx, selectors: list[dict], ranges: bool = False) -> Any:
    sel = select.evaluate(ctx, selectors)
    out = []
    for it in sel:
        if not isinstance(it.ea, int):
            rec = it.kind.to_record(it, ctx, ctx.opts.fields)
            out.append(rec)
            continue
        rec: dict[str, Any] = {"_t": "address", "ea": A(it.ea), "kind": it.kind.record,
                               "name": it.kind.get(it, "name", ctx)}
        if ranges:
            end = it.kind.get(it, "end", ctx)
            rec["end"] = end
            rec["size"] = (int(end) - it.ea) if end is not None else None
        if ctx.opts.fields:
            for f in ctx.opts.fields:
                rec.setdefault(f, it.kind.get(it, f, ctx))
        out.append(rec)
    if not out:
        ctx.set_status(Exit.NEGATIVE)
    return out


@op("count")
def count(ctx: Ctx, selectors: list[dict]) -> dict:
    sel = select.evaluate(ctx, selectors)
    return {"_t": "count", "count": len(sel), "items": [
        it.kind.to_record(it, ctx, None) for it in sel]}

