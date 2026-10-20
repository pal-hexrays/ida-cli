"""xrefs and callgraph."""

from __future__ import annotations

from typing import Any

import ida_funcs
import ida_name

from ...errors import Exit, IdaxError
from ...lang.graph import render
from .. import select
from ..context import A, Ctx
from ..kinds import KINDS
from ..kinds.code import XREF_TYPES
from ..kinds.functions import callees, callers, chunks
from ..rpc import op
from .common import records, selection


def _targets(ctx: Ctx, sel: Any, direction: str) -> list[int]:
    """Addresses whose references are followed.  For --from, a function
    selection means every instruction of the function."""
    out: list[int] = []
    for it in sel:
        if not isinstance(it.ea, int):
            continue
        if direction == "from":
            if it.kind.name == "function":
                from ..kinds.base import iter_heads

                for s, e in chunks(it.obj):
                    out.extend(iter_heads(s, e))
                continue
            if it.end is not None:
                from ..kinds.base import iter_heads

                out.extend(iter_heads(it.ea, it.end))
                continue
        out.append(it.ea)
    return out


@op("xrefs")
def xrefs(ctx: Ctx, selectors: list[dict], direction: str = "to", types: list[str] | None = None,
          depth: int = 1, flow: bool = False) -> Any:
    bad = [t for t in types or [] if t not in XREF_TYPES]
    if bad:
        raise IdaxError(Exit.USAGE, f"--type: unknown {', '.join(bad)} (one of {', '.join(XREF_TYPES)})", "USAGE")
    if depth < 1:
        raise IdaxError(Exit.USAGE, "--depth must be >= 1", "USAGE")
    sel = selection(ctx, selectors)
    xk = KINDS["xref"]
    frontier = _targets(ctx, sel, direction)
    seen_keys: set = set()
    visited: set[int] = set(frontier)
    out = []
    for level in range(1, depth + 1):
        nxt: list[int] = []
        for ea in frontier:
            items = xk.to_ea(ea, flow) if direction == "to" else xk.from_ea(ea, flow)  # type: ignore
            for it in items:
                if types and it.obj["type"] not in types:
                    continue
                if it.key in seen_keys:
                    continue
                seen_keys.add(it.key)
                it.cache["depth"] = level
                out.append(it)
                # follow: references to the function containing the referrer
                other = it.obj["from"] if direction == "to" else it.obj["to"]
                f = ida_funcs.get_func(other)
                follow = f.start_ea if f is not None else other
                if follow not in visited:
                    visited.add(follow)
                    nxt.append(follow)
        frontier = nxt
    recs = records(ctx, out)
    if depth > 1:
        for rec, it in zip(recs, out):
            rec["depth"] = it.cache["depth"]
    return recs


@op("callgraph")
def callgraph(ctx: Ctx, selectors: list[dict], direction: str = "callees", depth: int | None = None,
              graph: str | None = None) -> Any:
    sel = selection(ctx, selectors)
    roots = list(select.functions_of(ctx, sel))
    if not roots:
        raise IdaxError(Exit.EMPTY_SELECTION, "selection contains no function", "NOMATCH")
    max_depth = depth if depth is not None else 1 << 30
    edges: list[dict] = []
    nodes: dict[int, int] = {r.ea: 0 for r in roots}
    frontier = [r.ea for r in roots]
    level = 0
    seen_edges: set[tuple[int, int]] = set()
    while frontier and level < max_depth:
        level += 1
        nxt = []
        for ea in frontier:
            if direction == "callees":
                f = ida_funcs.get_func(ea)
                pairs = [(ea, t) for t in (callees(f) if f is not None else [])]
            else:
                pairs = [(c, ea) for c in callers(ea)]
            for src, dst in pairs:
                if (src, dst) in seen_edges:
                    continue
                seen_edges.add((src, dst))
                edges.append({"src": src, "dst": dst, "depth": level})
                other = dst if direction == "callees" else src
                if other not in nodes:
                    nodes[other] = level
                    if ida_funcs.get_func(other) is not None:
                        nxt.append(other)
        frontier = nxt

    def nm(ea: int) -> str:
        return ida_name.get_name(ea) or f"{ea:#x}"

    if graph:
        if graph not in ("dot", "gdl", "json"):
            raise IdaxError(Exit.USAGE, f"--graph {graph}: one of dot, gdl, json", "USAGE")
        gnodes = [{"id": nm(ea), "label": nm(ea), "ea": A(ea), "depth": d} for ea, d in nodes.items()]
        gedges = [{"src": nm(e["src"]), "dst": nm(e["dst"]), "depth": e["depth"]} for e in edges]
        name = ",".join(nm(r.ea) for r in roots)
        if graph == "json":
            return {"_t": "graph", "name": name, "nodes": gnodes, "edges": gedges}
        ctx.raw.append(render(gnodes, gedges, graph, f"callgraph {name}"))
        return []
    return [{"_t": "call", "from": A(e["src"]), "to": A(e["dst"]), "caller": nm(e["src"]),
             "callee": nm(e["dst"]), "depth": e["depth"]} for e in edges]
