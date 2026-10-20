"""Dynamic: debug and trace.  These run the target program and require
--allow-execute (or ICLI_ALLOW_EXECUTE=1); without it they exit 2."""

from __future__ import annotations

import argparse
from typing import Any

from ...errors import Exit, IdaxError, usage
from ...lang.values import parse_duration
from ..registry import Command, Invocation, register

DEBUGGERS = ("linux", "win32", "mac", "gdb", "windbg", "bochs", "dalvik", "pin", "replay")


def _require_execute(inv: Invocation) -> None:
    if not inv.g.allow_execute:
        raise IdaxError(Exit.USAGE, "this command runs the target program: pass --allow-execute", "EXECUTE")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--debugger", choices=DEBUGGERS)
    p.add_argument("--remote", metavar="HOST:PORT")
    p.add_argument("--timeout", default="60s", metavar="DURATION")


@register
class Debug(Command):
    name = "debug"
    group = "dynamic"
    summary = "run or attach under the debugger; record breakpoint hits; snapshot memory"
    subcommands = {"run": "start the program", "attach": "attach to a running process",
                   "snapshot": "run to an address and copy process memory into the database"}
    passthrough = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target")
        _common(p)
        if sub in ("run", "attach"):
            p.add_argument("--break", dest="breaks", action="append", default=[], metavar="SEL[:COND]")
            p.add_argument("--regs", metavar="LIST")
            p.add_argument("--dump", action="append", default=[], metavar="EXPR:SIZE")
        if sub == "attach":
            p.add_argument("--pid", type=int)
            p.add_argument("--name", dest="proc_name", metavar="PROC")
        if sub == "snapshot":
            p.add_argument("--at", metavar="SEL")

    def run(self, inv: Invocation) -> int:
        _require_execute(inv)
        a = inv.args
        inv.positionals(0)
        timeout = parse_duration(a.timeout)
        if a.sub == "snapshot":
            inv.call("debug.snapshot", {"at": inv.selectors([a.at]) if a.at else None, "timeout": timeout,
                                        "debugger": a.debugger, "remote": a.remote}, timeout=timeout + 60)
            return 0
        breaks = []
        for b in a.breaks:
            sel, _, cond = b.partition(":") if not b.startswith(("0x", ".")) or b.count(":") > 1 else (b, "", "")
            breaks.append({"selector": inv.selectors([sel])[0], "cond": cond or None})
        params: dict[str, Any] = {"breaks": breaks, "regs": [r for r in (a.regs or "").split(",") if r] or None,
                                  "dumps": a.dump or None, "timeout": timeout, "debugger": a.debugger,
                                  "remote": a.remote, "args": inv.passthrough}
        if a.sub == "attach":
            if a.pid is None and not a.proc_name:
                raise usage("icli debug attach: give --pid N or --name PROC")
            params["attach"] = {"pid": a.pid if a.pid is not None else _pid_of(a.proc_name)}
        inv.call("debug.run", params, timeout=timeout + 60)
        return 0


def _pid_of(name: str) -> int:
    import subprocess

    res = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    pids = [int(x) for x in res.stdout.split()]
    if len(pids) != 1:
        raise IdaxError(Exit.EMPTY_SELECTION, f"--name {name}: {len(pids)} matching processes", "NOMATCH")
    return pids[0]


@register
class Trace(Command):
    name = "trace"
    group = "dynamic"
    summary = "record an execution trace (or coverage) of the program"
    passthrough = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target")
        _common(p)
        p.add_argument("--mode", choices=("insn", "block", "func"), default="block")
        p.add_argument("--range", dest="trace_range", metavar="SEL")
        p.add_argument("--coverage", action="store_true")

    def run(self, inv: Invocation) -> int:
        _require_execute(inv)
        a = inv.args
        inv.positionals(0)
        timeout = parse_duration(a.timeout)
        inv.call("trace", {"mode": a.mode, "ranges": inv.selectors([a.trace_range]) if a.trace_range else None,
                           "coverage": a.coverage, "timeout": timeout, "debugger": a.debugger, "remote": a.remote,
                           "args": inv.passthrough}, timeout=timeout + 60)
        if a.coverage and inv.session is not None:
            inv.session.dirty = True
        return 0
