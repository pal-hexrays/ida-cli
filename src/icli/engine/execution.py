"""``icli exec``: run Python (or IDC) against the database.

Semantics follow ida-mcp's ``execute_python``: ``db`` (an ida-domain
Database) and ``ida_domain`` are pre-bound; a trailing expression is the
result, otherwise ``run(db)``, ``main(db)`` or ``execute(db)`` is called.
Changes made by the code are captured with IDB hooks and journaled as one
``exec`` record, so ``icli undo`` reverts a whole exec at once.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import sys
import traceback
from collections.abc import Iterable, Mapping
from typing import Any, Iterator

import ida_bytes
import ida_idaapi
import ida_idp

from ..errors import Exit, IdaxError
from . import journal, typesupport
from .context import Addr, Ctx

SESSIONS: dict[str, dict[str, Any]] = {}
"""Persistent namespaces for ``--session``; they live as long as this IDA
process (an ``icli serve`` worker)."""


class _Exit(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


class Recorder(ida_idp.IDB_Hooks):
    """Captures database changes as journal sub-records."""

    def __init__(self) -> None:
        super().__init__()
        self.changes: list[dict] = []
        self._pending_cmt: dict[tuple[int, bool], str | None] = {}
        self._pending_ti: dict[int, str | None] = {}

    def renamed(self, ea: int, new_name: str, local_name: bool, old_name: str) -> int:  # noqa: D102
        self.changes.append({"kind": "name", "ea": f"{ea:#x}", "key": None, "before": old_name or None,
                             "after": new_name or None})
        return 0

    def changing_cmt(self, ea: int, repeatable: bool, newcmt: str) -> int:  # noqa: D102
        self._pending_cmt[(ea, bool(repeatable))] = ida_bytes.get_cmt(ea, repeatable) or None
        return 0

    def cmt_changed(self, ea: int, repeatable: bool) -> int:  # noqa: D102
        key = (ea, bool(repeatable))
        before = self._pending_cmt.pop(key, None)
        self.changes.append({"kind": "comment", "ea": f"{ea:#x}", "key": "repeatable" if repeatable else "regular",
                             "before": before, "after": ida_bytes.get_cmt(ea, repeatable) or None})
        return 0

    def changing_ti(self, ea: int, new_type: Any, new_fnames: Any) -> int:  # noqa: D102
        self._pending_ti[ea] = typesupport.type_at(ea)
        return 0

    def ti_changed(self, ea: int, type: Any, fnames: Any) -> int:  # noqa: D102, A002
        self.changes.append({"kind": "type", "ea": f"{ea:#x}", "key": None,
                             "before": self._pending_ti.pop(ea, None), "after": typesupport.type_at(ea)})
        return 0

    def byte_patched(self, ea: int, old_value: int) -> int:  # noqa: D102
        new = ida_bytes.get_byte(ea)
        last = self.changes[-1] if self.changes else None
        if last and last["kind"] == "bytes" and int(last["ea"], 16) + last["key"] == ea:
            last["key"] += 1
            last["before"] += f"{old_value:02x}"
            last["after"] += f"{new:02x}"
        else:
            self.changes.append({"kind": "bytes", "ea": f"{ea:#x}", "key": 1, "before": f"{old_value:02x}",
                                 "after": f"{new:02x}"})
        return 0


def rollback(ctx: Ctx, changes: list[dict]) -> None:
    from . import edits

    for ch in reversed(changes):
        if ch["kind"] in edits.HANDLERS:
            try:
                edits.HANDLERS[ch["kind"]].set(int(ch["ea"], 16), ch["key"], ch["before"], {})
            except Exception:  # best effort: report, keep unwinding
                ctx.warnings.append({"_t": "diag", "level": "warning", "code": "ROLLBACK",
                                     "msg": f"could not roll back {ch['kind']} at {ch['ea']}"})


def _jsonable(v: Any) -> Any:
    if isinstance(v, Addr):
        return v
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, Mapping):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in v]
    if hasattr(v, "start_ea") and hasattr(v, "end_ea"):  # func_t, segment_t, ...
        return {"start_ea": v.start_ea, "end_ea": v.end_ea}
    return repr(v)


def to_records(result: Any) -> list[dict]:
    """A mapping is one record, an iterable of mappings a stream, and a
    scalar ``{"_t": "value", "value": ...}``."""
    if result is None:
        return []
    if isinstance(result, Mapping):
        rec = _jsonable(result)
        rec.setdefault("_t", "result")
        return [rec]
    if isinstance(result, (str, bytes, int, float, bool)):
        return [{"_t": "value", "value": _jsonable(result)}]
    if isinstance(result, Iterable):
        out = []
        for x in result:
            if isinstance(x, Mapping):
                rec = _jsonable(x)
                rec.setdefault("_t", "result")
                out.append(rec)
            else:
                out.append({"_t": "value", "value": _jsonable(x)})
        return out
    return [{"_t": "value", "value": _jsonable(result)}]


def _run_python(code: str, filename: str, ns: dict[str, Any], db: Any) -> Any:
    tree = ast.parse(code, filename=filename, mode="exec")
    last = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body.pop().value)
    exec(compile(tree, filename, "exec"), ns)  # noqa: S102 - the user's own code, by design
    if last is not None:
        return eval(compile(last, filename, "eval"), ns)  # noqa: S307
    for entry in ("run", "main", "execute"):
        fn = ns.get(entry)
        if callable(fn):
            res = fn(db)
            if isinstance(res, Iterator):
                res = list(res)
            return res
    return None


class ItemView(Mapping):
    """The record of an ``--each`` item; fields are computed on access."""

    def __init__(self, it: Any, ctx: Ctx) -> None:
        self._it, self._ctx = it, ctx

    def __getitem__(self, key: str) -> Any:
        if key not in self._it.kind.fields and not (self._it.record and key in self._it.record):
            raise KeyError(key)
        return self._it.kind.get(self._it, key, self._ctx)

    def __iter__(self) -> Iterator[str]:
        return iter(self._it.kind.fields)

    def __len__(self) -> int:
        return len(self._it.kind.fields)


def run(ctx: Ctx, code: str, *, filename: str = "<icli>", args: list[str] | None = None,
        each: list[dict] | None = None, session: str | None = None, lang: str = "py",
        no_save: bool = False, record_code: bool = True) -> tuple[list[dict], str, str, int]:
    """Returns (records, stdout, stderr, status)."""
    out, err = io.StringIO(), io.StringIO()
    rec = Recorder()
    rec.hook()
    records: list[dict] = []
    status = 0
    old_argv = sys.argv
    patched = _patch_qexit()
    try:
        sys.argv = [filename, *(args or [])]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                if lang == "idc":
                    records = to_records(_run_idc(code))
                elif each is not None:
                    from . import select

                    sel = select.evaluate(ctx, each)
                    for it in sel:
                        ns = _namespace(ctx, session)
                        ns["item"] = ItemView(it, ctx)
                        ns["ea"] = it.ea
                        records.extend(to_records(_run_python(code, filename, ns, ctx.db)))
                else:
                    ns = _namespace(ctx, session)
                    records = to_records(_run_python(code, filename, ns, ctx.db))
            except (SystemExit, _Exit) as e:
                code_ = e.code if isinstance(e, _Exit) else e.code
                status = int(code_) if isinstance(code_, int) else (0 if code_ is None else 1)
                if code_ is not None and not isinstance(code_, int):
                    print(code_, file=sys.stderr)
            except Exception:
                status = Exit.SCRIPT
                err.write(traceback.format_exc())
    except BaseException:
        # timeout/cancellation: roll the database back to before the call
        rec.unhook()
        rollback(ctx, rec.changes)
        raise
    finally:
        sys.argv = old_argv
        _unpatch_qexit(patched)
        rec.unhook()
    changes = rec.changes
    if changes and (ctx.opts.read_only or no_save):
        rollback(ctx, changes)
        if ctx.opts.read_only:
            raise IdaxError(Exit.READ_ONLY, f"the code modified the database ({len(changes)} change(s)); "
                            "rolled back", "READONLY")
    elif changes:
        sha = hashlib.sha256(code.encode()).hexdigest()
        entry = journal.append({"kind": "exec", "ea": None, "key": None, "before": None, "after": sha,
                                "sha256": sha, "code": code if record_code else None, "changes": changes,
                                "author": ctx.opts.author, "command": ctx.opts.command,
                                "message": ctx.opts.message or None})
        ctx.changes += 1
        ctx.warnings.append({"_t": "diag", "level": "info", "code": "JOURNAL",
                             "msg": f"journaled {len(changes)} change(s) as revision {entry['rev']}"})
    return records, out.getvalue(), err.getvalue(), status


def _namespace(ctx: Ctx, session: str | None) -> dict[str, Any]:
    import ida_domain

    if session:
        ns = SESSIONS.setdefault(session, {"__name__": "__icli_session__"})
    else:
        ns = {"__name__": "__icli_exec__"}
    ns["db"] = ctx.db
    ns["ida_domain"] = ida_domain
    return ns


def _run_idc(code: str) -> Any:
    import ida_expr

    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, code)
    if err:
        raise RuntimeError(f"IDC: {err}")
    if rv.vtype == ida_expr.VT_STR:
        return rv.c_str()
    if rv.vtype in (ida_expr.VT_LONG, ida_expr.VT_INT64):
        return rv.num if rv.vtype == ida_expr.VT_LONG else rv.i64
    if rv.vtype == ida_expr.VT_FLOAT:
        return float(rv.e)
    return None


def _patch_qexit() -> list[tuple[Any, str, Any]]:
    """qexit(n) inside the code sets the exit status instead of killing IDA."""
    patched = []

    def qexit(code: int = 0) -> None:
        raise _Exit(int(code))

    for modname in ("ida_pro", "idc"):
        mod = sys.modules.get(modname)
        if mod is not None and hasattr(mod, "qexit"):
            patched.append((mod, "qexit", mod.qexit))
            mod.qexit = qexit
    return patched


def _unpatch_qexit(patched: list[tuple[Any, str, Any]]) -> None:
    for mod, name, orig in patched:
        setattr(mod, name, orig)
