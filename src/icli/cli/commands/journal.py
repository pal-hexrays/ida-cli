"""Journal commands: apply, log, undo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ...errors import Exit, IcliError, usage
from ..registry import Invocation, register, stdin_lines
from .edit import Edit


def read_records(source: str) -> list[dict]:
    lines = stdin_lines() if source == "-" else _lines(source)
    out = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError as error:
            raise usage(f"{source}:{i}: not a JSON record: {error}")
        if isinstance(rec, dict) and "records" in rec and isinstance(rec["records"], list):
            out.extend(rec["records"])  # a -f json document
        elif isinstance(rec, dict):
            out.append(rec)
    return out


def _lines(path: str) -> list[str]:
    try:
        text = Path(path).read_text()
    except OSError as error:
        raise IcliError(Exit.NOT_FOUND, f"{path}: {error.strerror}", "NOTFOUND")
    try:
        return [json.dumps(json.loads(text))]  # one (possibly indented) -f json document
    except json.JSONDecodeError:
        return text.splitlines()


@register
class Apply(Edit):
    name = "apply"
    group = "journal"
    summary = "replay journal records (or query records carrying the same fields)"

    def configure(self, p: argparse.ArgumentParser) -> None:
        super().configure(p)
        p.add_argument("--on-conflict", choices=("fail", "skip", "ours", "theirs"), default="fail")
        p.add_argument("--only", metavar="KIND[,KIND...]", help="rename, type, comment, tags, ...")
        p.add_argument("--rebase", action="store_true", help="translate addresses by function matching")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals(0)
        if len(rest) > 1:
            raise usage("icli apply: expected one journal file or -")
        records = read_records(rest[0] if rest else "-")
        only = [k for k in (a.only or "").split(",") if k] or None
        return self.call(inv, "apply", {"records": records, "on_conflict": a.on_conflict, "only": only,
                                        "rebase": a.rebase})


@register
class Log(Edit):
    name = "log"
    group = "journal"
    summary = "print the journal, oldest first"
    edits = False

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--since", metavar="REV|TIME|DURATION")
        p.add_argument("--author", metavar="USER")
        p.add_argument("--kind", metavar="KIND[,KIND...]")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals(0)
        if inv.emitter.format == "text" and not inv.g.output.template:
            inv.emitter.use_template("{rev:>5}  {time}  {author:<10.10}  {kind:<10} {ea:<12} "
                                     "{before} -> {after}")
        inv.call("log", {"since": a.since, "author": a.author, "kind": a.kind,
                         "selectors": inv.selectors(rest) if rest else None}, need="loaded")
        return 0


@register
class Undo(Edit):
    name = "undo"
    group = "journal"
    summary = "revert the last N journal entries (or back to a revision)"

    def configure(self, p: argparse.ArgumentParser) -> None:
        super().configure(p)
        g = p.add_mutually_exclusive_group()
        g.add_argument("--to", type=int, metavar="REV")
        g.add_argument("-n", type=int, default=1, metavar="N")

    def run(self, inv: Invocation) -> int:
        inv.positionals(0)
        return self.call(inv, "undo", {"to": inv.args.to, "n": inv.args.n})
