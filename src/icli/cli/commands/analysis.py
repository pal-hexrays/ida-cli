"""Triage over a database (info) and analysis commands (analyze, status)."""

from __future__ import annotations

import argparse
import json
import sys
import time

from ...errors import Exit
from ..registry import Command, Invocation, register


@register
class Info(Command):
    name = "info"
    group = "triage"
    summary = "summarise a database"

    def run(self, inv: Invocation) -> int:
        inv.positionals()
        session = inv.open()
        inv.call("info", {"cache_key": session.target.key})
        return 0


@register
class Status(Command):
    name = "status"
    group = "analysis"
    summary = "lifecycle state, pending analysis, lock holder, journal length"
    needs = "loaded"

    def run(self, inv: Invocation) -> int:
        inv.positionals()
        session = inv.open()
        lock = {"pid": session.handle.instance.pid, "backend": session.handle.instance.backend,
                "record": session.handle.instance.record_id} if session.handle else None
        inv.call("status", {"lock": lock}, need="loaded")
        return 0


PASSES = ["lumina", "pdb", "dwarf", "rtti", "eh", "golang", "rust", "swift", "objc", "findmain", "decompile"]
DEFAULT_PASSES = ["flirt", "til", "final"]


@register
class Analyze(Command):
    name = "analyze"
    group = "analysis"
    summary = "bring the database to analyzed (or enriched with --with)"
    needs = "loaded"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("--reanalyze", action="store_true", help="discard analysis, keep user edits")
        p.add_argument("--with", dest="with_", metavar="PASS[,PASS...]", action="append", default=[])
        p.add_argument("--without", metavar="PASS[,PASS...]", action="append", default=[])
        p.add_argument("--sig", action="append", default=[], metavar="NAME")
        p.add_argument("--til", action="append", default=[], metavar="NAME")
        p.add_argument("--progress", action="store_true", help="progress as JSON lines on stderr")

    def run(self, inv: Invocation) -> int:
        from ...errors import usage
        from .. import config

        a = inv.args
        rest = inv.positionals()
        passes = [x for s in a.with_ for x in s.split(",") if x]
        if not passes:
            passes = list((config.CONFIG.get("analyze") or {}).get("with", []))
        unknown = [x for x in passes if x not in PASSES]
        if unknown:
            raise usage(f"--with: unknown pass {', '.join(unknown)} (known: {', '.join(PASSES)})")
        without = [x for s in a.without for x in s.split(",") if x]
        bad = [x for x in without if x not in DEFAULT_PASSES + PASSES]
        if bad:
            raise usage(f"--without: unknown pass {', '.join(bad)} (known: {', '.join(DEFAULT_PASSES)})")
        session = inv.open()
        started = time.monotonic()
        pre = {"sigs": a.sig, "tils": a.til, "without": without, "reanalyze": a.reanalyze,
               "selectors": inv.selectors(rest) if rest else None}
        if a.progress:
            sys.stderr.write(json.dumps({"_t": "progress", "queue": "all", "pct": 0}) + "\n")
        inv.call("analyze.prepare", pre, need="loaded", emit=False)
        session.ensure("analyzed")
        if session.partial:
            inv.set_status(Exit.PARTIAL)
        res_records = []
        for p in passes:
            if a.progress:
                sys.stderr.write(json.dumps({"_t": "progress", "pass": p}) + "\n")
            r = inv.call("analyze.pass", {"name": p}, need="analyzed", emit=False)
            res_records.extend(r.get("records", []))
        if passes:
            inv.call("lifecycle.mark", {"enriched": passes}, need="analyzed", emit=False)
        state = session.state()
        inv.emit([{"_t": "analysis", "state": state, "passes": res_records,
                   "seconds": round(time.monotonic() - started, 3)}])
        if a.progress:
            sys.stderr.write(json.dumps({"_t": "progress", "queue": "all", "pct": 100}) + "\n")
        return 0
