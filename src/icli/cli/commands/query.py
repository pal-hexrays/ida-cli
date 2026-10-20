"""Query commands: list, show, disasm, decompile, xrefs, callgraph, search, resolve."""

from __future__ import annotations

import argparse
from typing import Any

from ...errors import Exit, usage
from ..registry import Invocation, register
from .base import Remote

LIST_KINDS = ["functions", "names", "strings", "imports", "exports", "entries", "segments", "xrefs", "types",
              "tils", "sigs", "comments", "bookmarks", "tags", "problems", "fixups", "blocks", "patches",
              "lvars", "switches"]


@register
class List(Remote):
    name = "list"
    group = "query"
    summary = "list objects of a kind"
    op = "list"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("kind", choices=LIST_KINDS, metavar="kind")
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--where", metavar="EXPR")
        p.add_argument("--match", metavar="GLOB")
        p.add_argument("--regex", metavar="RE")
        p.add_argument("--sort", metavar="FIELD[:desc]")
        p.add_argument("-n", "--limit", type=int, metavar="N")
        p.add_argument("--count", action="store_true")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        a = inv.args
        if a.where:
            from ...lang import expr

            expr.parse(a.where)
        if a.regex:
            import re

            try:
                re.compile(a.regex)
            except re.error as error:
                raise usage(f"--regex: {error}")
        return {"kind": a.kind, "selectors": inv.selectors(rest) if rest else None, "where": a.where,
                "match": a.match, "regex": a.regex, "sort": a.sort, "limit": a.limit, "count": a.count}

    def run(self, inv: Invocation) -> int:
        if inv.args.count and inv.emitter.format == "text" and not inv.g.output.template:
            inv.emitter.use_template("{count}")
        return super().run(inv)


@register
class Resolve(Remote):
    name = "resolve"
    group = "query"
    summary = "evaluate selectors and print the resulting addresses"
    op = "resolve"
    selectors_required = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--ranges", action="store_true", help="print start, end and size")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        return {"selectors": inv.selectors(rest), "ranges": inv.args.ranges}

    def run(self, inv: Invocation) -> int:
        status = super().run(inv)
        if not inv.produced and not inv.g.show_code:
            inv.set_status(Exit.NEGATIVE)
        return status
