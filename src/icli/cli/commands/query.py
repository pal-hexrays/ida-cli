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


@register
class Show(Remote):
    name = "show"
    group = "query"
    summary = "everything known about each address"
    op = "show"
    selectors_required = True

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        return {"selectors": inv.selectors(rest)}


@register
class Disasm(Remote):
    name = "disasm"
    group = "query"
    summary = "disassembly listing (whole functions for function selectors)"
    op = "disasm"
    raw_field = "line"
    selectors_required = True
    optional_values = {"--bytes": ("8", str.isdigit),
                       "--graph": ("dot", lambda t: t in ("dot", "gdl", "json")),
                       "--microcode": ("lvars", lambda t: False)}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--bytes", type=int, metavar="N", help="show opcode bytes")
        p.add_argument("--no-xrefs", action="store_true")
        p.add_argument("--no-comments", action="store_true")
        p.add_argument("--no-prefix", action="store_true")
        p.add_argument("--syntax", metavar="NAME")
        p.add_argument("--graph", choices=("dot", "gdl", "json"))
        p.add_argument("--microcode", metavar="MATURITY")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        a = inv.args
        return {"selectors": inv.selectors(rest), "bytes": a.bytes, "xrefs": not a.no_xrefs,
                "comments": not a.no_comments, "prefix": not a.no_prefix, "syntax": a.syntax,
                "graph": a.graph, "microcode": a.microcode}

    def run(self, inv: Invocation) -> int:
        a = inv.args
        if inv.emitter.format == "text" and not inv.g.output.template:
            inv.emitter.use_template("{text}" if a.microcode else "{line}")
        return super().run(inv)


@register
class Decompile(Remote):
    name = "decompile"
    group = "query"
    summary = "decompile the functions containing the selected addresses"
    op = "decompile"
    raw_field = "pseudocode"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--all", action="store_true", help="every non-library function")
        p.add_argument("--with-types", action="store_true")
        p.add_argument("--at-line", action="store_true")
        p.add_argument("--ctree", action="store_true")
        p.add_argument("--line-map", action="store_true")
        p.add_argument("--fresh", action="store_true")
        p.add_argument("--hexrays-option", action="append", default=[], metavar="[+|-]NAME,...")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        a = inv.args
        if not rest and not a.all:
            raise usage("icli decompile: give selectors or --all")
        directives: list[str] = []
        if a.hexrays_option:
            from .. import settings

            spec = ",".join(x.strip() for opt in a.hexrays_option for x in opt.split(",") if x.strip())
            spec = ",".join(x if x[0] in "+-" else "+" + x for x in spec.split(","))
            directives = settings.parse([f"hexrays.HEXOPTIONS={spec}"]).hexrays
        return {"selectors": inv.selectors(rest) if rest else None, "all": a.all, "with_types": a.with_types,
                "at_line": a.at_line, "ctree": a.ctree, "line_map": a.line_map, "fresh": a.fresh,
                "hexrays_directives": directives}

    def run(self, inv: Invocation) -> int:
        a = inv.args
        if inv.emitter.format == "text" and not inv.g.output.template:
            if a.at_line:
                inv.emitter.use_template("{func}:{line}: {text}")
            elif not a.ctree:
                inv.emitter.use_template("{pseudocode}\\n")
        if inv.emitter.format == "raw" and a.at_line:
            inv.emitter.raw_field = "text"
        return super().run(inv)


@register
class Xrefs(Remote):
    name = "xrefs"
    group = "query"
    summary = "cross-references to (default) or from the selection"
    op = "xrefs"
    selectors_required = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        d = p.add_mutually_exclusive_group()
        d.add_argument("--to", dest="direction", action="store_const", const="to")
        d.add_argument("--from", dest="direction", action="store_const", const="from")
        p.add_argument("--type", action="append", default=[], metavar="T",
                       help="call, jump, flow, read, write, offset, text, info")
        p.add_argument("--depth", type=int, default=1, metavar="N")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        a = inv.args
        types = [t for x in a.type for t in x.split(",") if t]
        return {"selectors": inv.selectors(rest), "direction": a.direction or "to", "types": types or None,
                "depth": a.depth, "flow": "flow" in types}


@register
class Callgraph(Remote):
    name = "callgraph"
    group = "query"
    summary = "call graph rooted at the selected functions"
    op = "callgraph"
    selectors_required = True
    optional_values = {"--graph": ("dot", lambda t: t in ("dot", "gdl", "json"))}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        d = p.add_mutually_exclusive_group()
        d.add_argument("--callers", dest="direction", action="store_const", const="callers")
        d.add_argument("--callees", dest="direction", action="store_const", const="callees")
        p.add_argument("--depth", type=int, metavar="N")
        p.add_argument("--graph", choices=("dot", "gdl", "json"))

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        a = inv.args
        if a.depth is not None and a.depth < 1:
            raise usage("--depth must be >= 1")
        return {"selectors": inv.selectors(rest), "direction": a.direction or "callees", "depth": a.depth,
                "graph": a.graph}


SEARCH_MODES = ("bytes", "imm", "insn", "text", "pseudo", "string", "crypto")


@register
class Search(Remote):
    name = "search"
    group = "query"
    summary = "search the selected ranges (default: everything)"
    op = "search"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--bytes", metavar="PATTERN")
        g.add_argument("--imm", metavar="VALUE")
        g.add_argument("--insn", metavar="PATTERN")
        g.add_argument("--text", metavar="RE")
        g.add_argument("--pseudo", metavar="RE")
        g.add_argument("--string", metavar="RE")
        g.add_argument("--crypto", action="store_true")
        p.add_argument("-n", "--limit", type=int, metavar="N")

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        import re

        from ...lang.values import parse_int

        a = inv.args
        mode = next(m for m in SEARCH_MODES if getattr(a, m) not in (None, False))
        value: Any = getattr(a, mode)
        if mode == "imm":
            value = parse_int(value)
        elif mode in ("text", "pseudo", "string"):
            try:
                re.compile(value)
            except re.error as error:
                raise usage(f"--{mode}: bad regular expression: {error}")
        elif mode == "bytes":
            hexs = value.replace(" ", "")
            if not hexs or not re.fullmatch(r"([0-9a-fA-F?]{2})+", hexs):
                raise usage(f"--bytes {value!r}: expected hex bytes, ?? for wildcards")
        elif mode == "crypto":
            value = None
        return {"mode": mode, "value": value, "selectors": inv.selectors(rest) if rest else None,
                "limit": a.limit}

    def run(self, inv: Invocation) -> int:
        status = super().run(inv)
        if not inv.produced and not inv.g.show_code:
            inv.set_status(Exit.NEGATIVE)
        return status
