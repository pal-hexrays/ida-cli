"""Triage: identify, info, loaders, processors."""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

from ...errors import Exit, IcliError, combine, usage
from ..registry import Command, Invocation, register

HASHES = ("md5", "sha1", "sha256", "ssdeep", "tlsh")


@register
class Identify(Command):
    name = "identify"
    group = "triage"
    summary = "describe files without creating a database"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="file")
        p.add_argument("--hash", metavar="ALGO[,ALGO...]", default=",".join(HASHES))
        p.add_argument("--deep", action="store_true", help="also load into a scratch database")

    def run(self, inv: Invocation) -> int:
        from ..identify import identify

        files = inv.args.items
        if not files:
            raise usage("icli identify: expected file(s)")
        algos = [a.strip().lower() for a in inv.args.hash.split(",") if a.strip()]
        bad = [a for a in algos if a not in HASHES + ("sha512",)]
        if bad:
            raise usage(f"--hash: unknown {', '.join(bad)} (one of {', '.join(HASHES)}, sha512)")
        status = 0
        for f in files:
            p = Path(f)
            if not p.is_file():
                inv.emitter.diag("error", "NOTFOUND", f"{f}: no such file")
                status = combine(status, Exit.NOT_FOUND)
                continue
            rec = identify(p, algos, deep=inv.args.deep)
            if not rec["loaders"]:
                status = combine(status, Exit.NEGATIVE)
            inv.emit([rec])
        return status


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
class Loaders(Command):
    name = "loaders"
    group = "triage"
    summary = "list loaders; with a file, those accepting it in priority order"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="file")

    def run(self, inv: Invocation) -> int:
        from .. import local

        if not inv.args.items:
            inv.emit([{"_t": "loader", **x} for x in local.all_loaders()])
            return 0
        status = 0
        for f in inv.args.items:
            p = Path(f)
            if not p.is_file():
                raise IcliError(Exit.NOT_FOUND, f"{f}: no such file", "NOTFOUND")
            found = local.loaders_for(p)
            if not found:
                status = Exit.NEGATIVE
            inv.emit([{"_t": "loader", "file": str(p), "rank": i + 1, **x} for i, x in enumerate(found)])
        return status


@register
class Processors(Command):
    name = "processors"
    group = "triage"
    summary = "list processor modules, variants, decompiler and assembler availability"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="glob")

    def run(self, inv: Invocation) -> int:
        from .. import local

        pattern = inv.args.items[0] if inv.args.items else "*"
        out = []
        for m in local.processors():
            names = [m["module"]] + [v["name"] for v in m["variants"]]
            if any(fnmatch.fnmatch(n.lower(), pattern.lower()) for n in names):
                out.append({"_t": "processor", "module": m["module"], "family": m["family"],
                            "variants": [v["name"] for v in m["variants"] if not v["hidden"]],
                            "decompiler": m["decompiler"], "assembler": m["assembler"]})
        if inv.emitter.format == "text" and not inv.g.output.template:
            for r in out:
                sys.stdout.write(f"{r['module']:<10} {r['family']:<44} dec={r['decompiler'] or '-':<8} "
                                 f"asm={'yes' if r['assembler'] else 'no':<3} {', '.join(r['variants'][:6])}"
                                 f"{' ...' if len(r['variants']) > 6 else ''}\n")
            return 0 if out else Exit.NEGATIVE
        inv.emit(out)
        return 0 if out else Exit.NEGATIVE
