"""Edit commands: rename, comment, type, func, make, patch, tag."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from ...errors import Exit, IdaxError, usage
from ...lang.values import parse_int
from ..registry import Command, Invocation, register, stdin_lines
from .base import add_edit_options


class Edit(Command):
    """Edit commands share --message/--force, journaling and dry-run status."""

    edits = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        add_edit_options(p)

    def call(self, inv: Invocation, op: str, params: dict[str, Any]) -> int:
        if inv.g.show_code:
            from ..showcode import show_code

            inv.emitter.raw([show_code(op, params)])
            return 0
        inv.call(op, params, ctx={"message": getattr(inv.args, "message", None),
                                  "force": getattr(inv.args, "force", False)})
        if not inv.g.dry_run and inv.session is not None:
            inv.session.dirty = True
        return 0


def _split_last(rest: list[str], what: str, cmd: str) -> tuple[list[str], str]:
    if len(rest) < 2:
        raise usage(f"icli {cmd}: expected selector(s) and {what}")
    return rest[:-1], rest[-1]


def _mapping_lines(lines: list[str], origin: str) -> list[dict]:
    from ...lang import selector as psel

    rows = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("{"):
            try:
                rec = json.loads(s)
            except json.JSONDecodeError as error:
                raise usage(f"{origin}:{i}: bad JSON: {error}")
            if rec.get("_t") == "diag":
                continue
            ea = rec.get("ea") or rec.get("start") or rec.get("from")
            name = rec.get("name")
            if ea is None or not name:
                raise usage(f"{origin}:{i}: JSON rows need ea and name")
            rows.append({"selector": psel.parse(str(ea)), "name": name})
            continue
        if "\t" not in s:
            raise usage(f"{origin}:{i}: expected 'selector<TAB>name'")
        sel, name = s.split("\t", 1)
        rows.append({"selector": psel.parse(sel.strip()), "name": name.strip()})
    return rows


@register
class Rename(Edit):
    name = "rename"
    group = "edit"
    summary = "set names (templates, maps, local variables)"
    rest_min = 1

    def configure(self, p: argparse.ArgumentParser) -> None:
        super().configure(p)
        p.add_argument("--local", action="store_true")
        p.add_argument("--public", action="store_true")
        p.add_argument("--weak", action="store_true")
        p.add_argument("--regex", metavar="s/RE/REPL/")
        p.add_argument("--lvar", metavar="FUNC", help="rename a decompiler local variable of FUNC")
        p.add_argument("--unique", action="store_true", help="suffix _1, _2 on collision")
        p.add_argument("--clear", action="store_true", help="restore the dummy name")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals()
        base = {"local": a.local, "public": a.public, "weak": a.weak, "unique": a.unique, "force": a.force}
        if len(rest) == 1 and not (a.regex or a.clear) and (rest[0] == "-" or Path(rest[0]).is_file()):
            lines = stdin_lines() if rest[0] == "-" else Path(rest[0]).read_text().splitlines()
            return self.call(inv, "rename", {**base, "mapping": _mapping_lines(lines, rest[0])})
        if a.lvar:
            sels, new = _split_last(rest, "a new name", self.name)
            return self.call(inv, "rename", {**base, "lvar": inv.selectors([a.lvar]), "selectors":
                                             inv.selectors(sels), "name": new})
        if a.regex or a.clear:
            if not rest:
                raise usage("icli rename: expected selector(s)")
            return self.call(inv, "rename", {**base, "selectors": inv.selectors(rest), "regex": a.regex,
                                             "clear": a.clear})
        sels, new = _split_last(rest, "a name", self.name)
        from ...lang import template

        template.parse(new, record_newline=False)  # validate
        return self.call(inv, "rename", {**base, "selectors": inv.selectors(sels), "name": new})


@register
class Comment(Edit):
    name = "comment"
    group = "edit"
    summary = "set (or with empty text remove) a comment"
    rest_min = 2

    def configure(self, p: argparse.ArgumentParser) -> None:
        super().configure(p)
        p.add_argument("--kind", default="regular",
                       choices=("regular", "repeatable", "anterior", "posterior", "function", "pseudocode"))
        p.add_argument("--append", action="store_true")

    def run(self, inv: Invocation) -> int:
        rest = inv.positionals()
        sels, text = _split_last(rest, "text", self.name)
        return self.call(inv, "comment", {"selectors": inv.selectors(sels), "text": text,
                                          "kind": inv.args.kind, "append": inv.args.append,
                                          "force": inv.args.force})


@register
class Tag(Edit):
    name = "tag"
    group = "edit"
    summary = "attach free-form tags (and a background colour) to items"
    rest_min = 1
    overrides = frozenset({"--color"})

    def configure(self, p: argparse.ArgumentParser) -> None:
        super().configure(p)
        p.add_argument("--remove", action="store_true")
        p.add_argument("--color", metavar="RRGGBB")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals()
        if not rest:
            raise usage("icli tag: expected a selector and tag(s)")
        sel, tags = rest[0], rest[1:]
        if not tags and not a.color and not a.remove:
            raise usage("icli tag: expected tag(s) or --color")
        if a.color and not re.fullmatch(r"[0-9a-fA-F]{6}", a.color):
            raise usage(f"--color {a.color}: expected rrggbb")
        return self.call(inv, "tag", {"selectors": inv.selectors([sel]), "tags": tags, "remove": a.remove,
                                      "color": a.color})


@register
class Type(Edit):
    name = "type"
    group = "edit"
    summary = "apply, inspect, import and dump C types"
    subcommands = {"set": "apply a C declaration", "get": "print the type at an address",
                   "add": "parse declarations into local types", "import": "copy types from a til or database",
                   "del": "delete local types", "dump": "local types as a C header",
                   "op": "operand representation", "callsite": "override the prototype at a call site"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/arguments")
        add_edit_options(p)
        if sub == "set":
            p.add_argument("--propagate", action="store_true")
            p.add_argument("--lvar", metavar="FUNC", help="type a local variable of FUNC")
        elif sub == "add":
            p.add_argument("-I", dest="include", action="append", default=[], metavar="DIR")
            p.add_argument("-D", dest="define", action="append", default=[], metavar="NAME[=VALUE]")
            p.add_argument("--target", metavar="TRIPLE")
            p.add_argument("--parser", choices=("clang", "legacy"), default="clang")
            p.add_argument("--replace", action="store_true")
        elif sub == "import":
            p.add_argument("--replace", action="store_true")
        elif sub == "op":
            p.add_argument("--operand", "-n", type=int, required=True, metavar="N")
            p.add_argument("--as", dest="as_", required=True, metavar="KIND[:ARG]")

    def run(self, inv: Invocation) -> int:
        sub = inv.args.sub
        a = inv.args
        if sub == "dump":
            rest = inv.positionals(0)
            if inv.emitter.format == "text" or inv.emitter.format == "raw":
                inv.emitter.raw_field = "text"
                if inv.emitter.format == "text" and not inv.g.output.template:
                    inv.emitter.use_template("{text}\\c")
            inv.call("type.dump", {"names": rest or None})
            return 0
        if sub == "get":
            rest = inv.positionals(1)
            inv.call("type.get", {"selectors": inv.selectors(rest)})
            return 0
        if sub == "set":
            rest = inv.positionals(2)
            sels, decl = _split_last(rest, "a declaration", "type set")
            if a.lvar:
                return self.call(inv, "type.set", {"selectors": inv.selectors(sels), "decl": decl,
                                                   "lvar": inv.selectors([a.lvar]), "force": a.force})
            return self.call(inv, "type.set", {"selectors": inv.selectors(sels), "decl": decl,
                                               "propagate": a.propagate, "force": a.force})
        if sub == "add":
            rest = inv.positionals(1)
            if len(rest) != 1:
                raise usage("icli type add: expected one header file or -")
            text = sys.stdin.read() if rest[0] == "-" else _read(rest[0])
            args = [f"-I{Path(d).resolve()}" for d in a.include] + [f"-D{d}" for d in a.define]
            if a.target:
                args.append(f"-target {a.target}")
            if rest[0] != "-":
                args.append(f"-I{Path(rest[0]).resolve().parent}")
            return self.call(inv, "type.add", {"text": text, "parser": a.parser, "args": args,
                                               "replace": a.replace})
        if sub == "import":
            rest = inv.positionals(2)
            if len(rest) < 2:
                raise usage("icli type import: expected a source and type name(s)")
            source, names = rest[0], rest[1:]
            definitions = None
            if source.endswith((".i64", ".idb")) or (Path(source).is_file() and not source.endswith(".til")):
                definitions = self._definitions_from(inv, source, names)
            elif Path(source).exists():
                source = str(Path(source).resolve())
            return self.call(inv, "type.import", {"source": source, "names": names, "definitions": definitions,
                                                  "replace": a.replace})
        if sub == "del":
            rest = inv.positionals(1)
            if not rest:
                raise usage("icli type del: expected type name(s)")
            return self.call(inv, "type.del", {"names": rest})
        if sub == "op":
            rest = inv.positionals(1)
            return self.call(inv, "type.op", {"selectors": inv.selectors(rest), "operand": a.operand,
                                              "as_": a.as_, "force": a.force})
        if sub == "callsite":
            rest = inv.positionals(2)
            sels, decl = _split_last(rest, "a prototype", "type callsite")
            return self.call(inv, "type.callsite", {"selectors": inv.selectors(sels), "decl": decl,
                                                    "force": a.force})
        raise usage(f"icli type: unknown subcommand {sub}")

    def _definitions_from(self, inv: Invocation, source: str, names: list[str]) -> dict[str, str]:
        from ..opening import open_session

        s = open_session(source, inv.g, inv.emitter.diag)
        try:
            res = s.call("type.definitions", {"names": names})
        finally:
            s.close(save=False)
        return {r["name"]: r["decl"] for r in res["records"]}


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError as error:
        raise IdaxError(Exit.NOT_FOUND, f"{path}: {error.strerror}", "NOTFOUND")


@register
class Func(Edit):
    name = "func"
    group = "edit"
    summary = "create, delete or change functions (bounds, flags, frame, chunks)"
    subcommands = {"create": "create a function", "delete": "delete a function (keeping instructions)",
                   "set": "change bounds, flags or frame", "tail": "add or remove a chunk"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        add_edit_options(p)
        if sub == "create":
            p.add_argument("--end", metavar="ADDR")
        elif sub == "set":
            p.add_argument("--start", metavar="ADDR")
            p.add_argument("--end", metavar="ADDR")
            p.add_argument("--flags", metavar="+FLAG,-FLAG")
            p.add_argument("--frame", type=int, metavar="SIZE", help="local variables size")
        elif sub == "tail":
            g = p.add_mutually_exclusive_group(required=True)
            g.add_argument("--add", metavar="START-END")
            g.add_argument("--remove", metavar="START")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        sub = a.sub
        rest = inv.positionals(1)
        if not rest:
            raise usage(f"icli func {sub}: expected selector(s)")
        sels = inv.selectors(rest)
        if sub == "create":
            return self.call(inv, "func.create", {"selectors": sels,
                                                  "end": parse_int(a.end) if a.end else None})
        if sub == "delete":
            return self.call(inv, "func.delete", {"selectors": sels})
        if sub == "set":
            flags = [f.strip() for f in (a.flags or "").split(",") if f.strip()]
            if not (a.start or a.end or flags or a.frame is not None):
                raise usage("icli func set: give --start, --end, --flags or --frame")
            return self.call(inv, "func.set", {"selectors": sels, "start": parse_int(a.start) if a.start else None,
                                               "end": parse_int(a.end) if a.end else None, "flags": flags or None,
                                               "frame": a.frame})
        if sub == "tail":
            if a.add:
                start, sep, end = a.add.partition("-")
                if not sep:
                    raise usage("--add expects START-END")
                return self.call(inv, "func.tail", {"selectors": sels, "add": [parse_int(start), parse_int(end)]})
            return self.call(inv, "func.tail", {"selectors": sels, "remove": parse_int(a.remove)})
        raise usage(f"icli func: unknown subcommand {sub}")


MAKE_KINDS = ("code", "byte", "word", "dword", "qword", "oword", "tbyte", "float", "double", "string", "array",
              "struct", "offset", "align", "unknown")


@register
class Make(Edit):
    name = "make"
    group = "edit"
    summary = "convert items: code, data, strings, arrays, structs, offsets, unknown"
    overrides = frozenset({"--base", "--encoding"})

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("kind", choices=MAKE_KINDS, metavar="kind")
        super().configure(p)
        p.add_argument("--count", type=int, metavar="N")
        p.add_argument("--type", metavar="NAME", help="struct type, or array element kind")
        p.add_argument("--base", metavar="ADDR")
        p.add_argument("--encoding", metavar="NAME")
        p.add_argument("--size", type=int, metavar="N")
        p.add_argument("--jumptable", metavar="table=ADDR,count=N[,elsize=..][,base=..][,default=..]")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals(1)
        if not rest:
            raise usage("icli make: expected selector(s)")
        return self.call(inv, "make", {"kind": a.kind, "selectors": inv.selectors(rest), "count": a.count,
                                       "type": a.type, "base": parse_int(a.base) if a.base else None,
                                       "encoding": a.encoding, "size": a.size, "jumptable": a.jumptable})


@register
class Patch(Edit):
    name = "patch"
    group = "edit"
    summary = "patch bytes, assemble, NOP out, revert"
    subcommands = {"bytes": "patch bytes", "asm": "assemble and patch", "nop": "replace items with NOPs",
                   "revert": "restore original bytes"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/arguments")
        add_edit_options(p)

    def run(self, inv: Invocation) -> int:
        sub = inv.args.sub
        if sub == "bytes":
            rest = inv.positionals(2)
            sels, hexdata = _split_last(rest, "hex bytes", "patch bytes")
            h = hexdata.replace(" ", "")
            if not h or not re.fullmatch(r"([0-9a-fA-F]{2})+", h):
                raise usage(f"icli patch bytes: bad hex {hexdata!r}")
            return self.call(inv, "patch.bytes", {"selectors": inv.selectors(sels), "hexdata": h})
        if sub == "asm":
            rest = inv.positionals(2)
            if len(rest) < 2:
                raise usage("icli patch asm: expected a selector and instruction(s)")
            return self.call(inv, "patch.asm", {"selectors": inv.selectors(rest[:1]), "lines": rest[1:]})
        if sub == "nop":
            rest = inv.positionals(1)
            if not rest:
                raise usage("icli patch nop: expected selector(s)")
            return self.call(inv, "patch.nop", {"selectors": inv.selectors(rest)})
        if sub == "revert":
            rest = inv.positionals(0)
            return self.call(inv, "patch.revert", {"selectors": inv.selectors(rest) if rest else None})
        raise usage(f"icli patch: unknown subcommand {sub}")
