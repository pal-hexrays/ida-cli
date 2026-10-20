"""debug and trace, on IDA's debugger API (the client enforces --allow-execute)."""

from __future__ import annotations

import time
from typing import Any

import ida_dbg
import ida_idd
import ida_kernwin

from ...errors import Exit, IdaxError
from .. import select
from ..context import A, Ctx
from ..rpc import op
from .common import selection, spans

DEFAULT_DEBUGGERS = {"darwin": "mac", "linux": "linux", "win32": "win32"}


def _load_debugger(name: str | None, remote: str | None) -> str:
    import platform
    import sys

    dbg = name or DEFAULT_DEBUGGERS.get(sys.platform, "linux")
    if platform.machine().lower() in ("arm64", "aarch64"):
        # the manual's backend names, mapped to this host's debugger modules
        dbg = {"mac": "arm_mac", "linux": "armlinux"}.get(dbg, dbg)
    is_remote = bool(remote) or dbg in ("gdb", "windbg")
    if not ida_dbg.load_debugger(dbg, is_remote):
        raise IdaxError(Exit.USAGE, f"debugger {dbg!r} is not available", "USAGE")
    if remote:
        import os

        host, _, port = remote.rpartition(":")
        ida_dbg.set_remote_debugger(host or "127.0.0.1", os.environ.get("ICLI_DEBUG_PASSWORD")
                                    or os.environ.get("IDX_DEBUG_PASSWORD") or "", int(port or 23946))
    return dbg


def _regs(names: list[str] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    wanted = names or [r for r in ("rip", "rsp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "pc", "sp", "lr",
                                   "x0", "x1", "eip", "esp", "eax")]
    for r in wanted:
        try:
            v = ida_dbg.get_reg_val(r)
        except Exception:
            if names:
                out[r] = None
            continue
        out[r] = A(v) if isinstance(v, int) else v
    return out


def _stack() -> list:
    trace = ida_idd.call_stack_t()
    if not ida_dbg.collect_stack_trace(ida_dbg.get_current_thread(), trace):
        return []
    return [A(f.callea) for f in trace]


def _dump(expr: str) -> dict:
    """``expr:size`` -- an address expression (or register) and a byte count."""
    from ...lang import selector as psel
    from .. import addresses

    where, _, size = expr.rpartition(":")
    try:
        ea = ida_dbg.get_reg_val(where)
    except Exception:
        ea = addresses.evaluate(psel.parse_addrexpr(where))[0]
    data = ida_idd.dbg_read_memory(ea, int(size, 0)) if hasattr(ida_idd, "dbg_read_memory") else \
        ida_dbg.read_dbg_memory(ea, int(size, 0))
    return {"expr": where, "ea": A(ea), "bytes": data.hex() if data else None}


def _event_loop(ctx: Ctx, timeout: float, on_suspend: Any) -> int:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            ida_dbg.exit_process()
            return Exit.TIMEOUT
        code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, int(min(remaining, 5)))
        if code == ida_dbg.PROCESS_EXITED or ida_dbg.get_process_state() == ida_dbg.DSTATE_NOTASK:
            return 0
        if code <= 0:
            continue
        if on_suspend(code) is False:
            ida_dbg.exit_process()
            return 0
        ida_dbg.continue_process()


@op("debug.run")
def debug_run(ctx: Ctx, breaks: list[dict] | None = None, regs: list[str] | None = None,
              dumps: list[str] | None = None, timeout: float = 60.0, debugger: str | None = None,
              remote: str | None = None, args: list[str] | None = None, attach: dict | None = None) -> list[dict]:
    _load_debugger(debugger, remote)
    ida_kernwin.cvar.batch = 1  # answer debugger prompts with their defaults (exceptions.cfg)
    for b in breaks or []:
        for ea in select.addresses_of(select.evaluate(ctx, [b["selector"]])):
            ida_dbg.add_bpt(ea, 0, ida_idd.BPT_SOFT)
            if b.get("cond"):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.get_bpt(ea, bpt):
                    bpt.condition = b["cond"]
                    ida_dbg.update_bpt(bpt)
    out: list[dict] = []
    if attach:
        if ida_dbg.attach_process(int(attach.get("pid") or -1), -1) <= 0:
            raise IdaxError(Exit.USAGE, f"cannot attach to {attach}", "USAGE")
    else:
        import ida_nalt

        if ida_dbg.start_process(ida_nalt.get_input_file_path(), " ".join(args or []), "") <= 0:
            raise IdaxError(Exit.LOAD, "cannot start the process under the debugger", "LOAD")

    def suspended(code: int) -> None:
        ea = ida_dbg.get_ip_val()
        rec = {"_t": "break", "ea": A(ea), "thread": ida_dbg.get_current_thread(), "regs": _regs(regs),
               "stack": _stack()}
        if dumps:
            rec["memory"] = [_dump(d) for d in dumps]
        out.append(rec)

    status = _event_loop(ctx, timeout, suspended)
    ctx.set_status(status)
    return out


@op("debug.snapshot")
def debug_snapshot(ctx: Ctx, at: list[dict] | None = None, timeout: float = 60.0, debugger: str | None = None,
                   remote: str | None = None) -> dict:
    import ida_nalt

    _load_debugger(debugger, remote)
    ida_kernwin.cvar.batch = 1
    from ..addresses import entry_point

    target = select.addresses_of(selection(ctx, at))[0] if at else entry_point()
    ida_dbg.add_bpt(target, 0, 4)
    if ida_dbg.start_process(ida_nalt.get_input_file_path(), "", "") <= 0:
        raise IdaxError(Exit.LOAD, "cannot start the process under the debugger", "LOAD")
    taken = {"ok": False}

    def suspended(code: int) -> bool:
        if ida_dbg.get_ip_val() == target:
            taken["ok"] = bool(ida_dbg.take_memory_snapshot(ida_dbg.SNAP_ALL_SEG if hasattr(
                ida_dbg, "SNAP_ALL_SEG") else 0))
            return False
        return True

    status = _event_loop(ctx, timeout, suspended)
    if status:
        ctx.set_status(status)
    from .. import lifecycle

    lifecycle.mark(analyzed=None)
    return {"_t": "snapshot", "ea": A(target), "taken": taken["ok"]}


@op("trace")
def trace(ctx: Ctx, mode: str = "block", ranges: list[dict] | None = None, coverage: bool = False,
          timeout: float = 60.0, debugger: str | None = None, remote: str | None = None,
          args: list[str] | None = None) -> list[dict]:
    import ida_nalt

    _load_debugger(debugger, remote)
    ida_kernwin.cvar.batch = 1
    enable = {"insn": ida_dbg.enable_insn_trace, "block": ida_dbg.enable_bblk_trace,
              "func": ida_dbg.enable_func_trace}.get(mode)
    if enable is None:
        raise IdaxError(Exit.USAGE, f"--mode {mode}: one of insn, block, func", "USAGE")
    from ..addresses import entry_point

    ida_dbg.add_bpt(entry_point(), 0, 4)
    if ida_dbg.start_process(ida_nalt.get_input_file_path(), " ".join(args or []), "") <= 0:
        raise IdaxError(Exit.LOAD, "cannot start the process under the debugger", "LOAD")
    started = {"on": False}

    def suspended(code: int) -> None:
        if not started["on"]:
            enable(True)
            started["on"] = True

    status = _event_loop(ctx, timeout, suspended)
    sp = spans(select.evaluate(ctx, ranges)) if ranges else None
    hits: dict[int, int] = {}
    out: list[dict] = []
    for i in range(ida_dbg.get_tev_qty()):
        ea = ida_dbg.get_tev_ea(i)
        if sp is not None and not any(s <= ea < e for s, e in sp):
            continue
        hits[ea] = hits.get(ea, 0) + 1
        if not coverage:
            out.append({"_t": "trace", "index": i, "ea": A(ea), "type": ida_dbg.get_tev_type(i),
                        "thread": ida_dbg.get_tev_tid(i)})
    if coverage:
        from .. import coverage as cov

        ctx.require_writable()
        cov.add(hits)
        out = [{"_t": "coverage", "ea": A(ea), "hits": n} for ea, n in sorted(hits.items())]
    ctx.set_status(status)
    return out
