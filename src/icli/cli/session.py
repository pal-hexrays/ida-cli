"""A database session: one ida-nexus lease, engine calls, analysis catch-up.

The engine (``icli.engine``) runs inside the IDA process.  A call is an
``execute_python`` snippet whose trailing expression is
``icli.engine.rpc.call(db, request)``; the worker imports this very package
(it runs on this venv's interpreter; for a GUI instance the source root is
put on ``sys.path``).  When the client's sources change, the engine modules
are reloaded in the worker.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..errors import Exit, IdaxError
from .target import Target

STATES = ["loaded", "analyzing", "analyzed", "enriched"]

_SRC_ROOT = str(Path(__file__).resolve().parents[2])
_digest: str | None = None


def source_digest() -> str:
    """Identity of the engine sources (file names, sizes and mtimes)."""
    global _digest
    if _digest is None:
        h = hashlib.sha256()
        pkg = Path(__file__).resolve().parents[1]
        for p in sorted(pkg.rglob("*.py")):
            st = p.stat()
            h.update(f"{p.relative_to(pkg)}:{st.st_size}:{st.st_mtime_ns};".encode())
        _digest = h.hexdigest()[:16]
    return _digest


_BOOTSTRAP = """\
import sys as _sys
if {root!r} not in _sys.path:
    _sys.path.insert(0, {root!r})
import icli.engine.rpc as _icli_rpc
if getattr(_icli_rpc, "DIGEST", None) != {digest!r}:
    for _m in [m for m in list(_sys.modules) if m == "icli" or m.startswith("icli.")]:
        del _sys.modules[_m]
    import icli.engine.rpc as _icli_rpc
    _icli_rpc.DIGEST = {digest!r}
_icli_rpc.call(db, {request!r})
"""


@dataclass
class LoadSpec:
    """Load options translated for ida-nexus (spawn-only)."""

    processor: str | None = None
    file_type: str | None = None
    image_base: int | None = None
    entry_point: int | None = None
    compiler: str | None = None
    no_segmentation: bool = False
    db_compression: str | None = None
    load_resources: bool = False
    first_pass_directives: tuple[str, ...] = ()
    second_pass_directives: tuple[str, ...] = ()
    plugin_options: str | None = None
    log_file: str | None = None
    post_load: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionOptions:
    analysis: str = "auto"              # auto | none | wait
    analysis_timeout: float | None = None
    read_only: bool = False
    no_server: bool = False
    exec_timeout: float | None = None
    keepalive: float = 0.0
    verbose: int = 0
    quiet: bool = False
    progress_json: bool = False


class Session:
    def __init__(self, target: Target, spec: LoadSpec, opts: SessionOptions,
                 diag: Callable[[str, str, str], None] | None = None) -> None:
        self.target = target
        self.spec = spec
        self.opts = opts
        self.diag = diag or (lambda level, code, msg: None)
        self.handle: Any = None
        self.fresh = False
        self.dirty = False
        self.partial = False
        self.saved = False
        self.gui = False
        self._ready = False

    # -- lifecycle -------------------------------------------------------------------

    def open(self) -> "Session":
        from ida_nexus import (
            DatabaseBusyError,
            DatabaseHandle,
            DatabaseOpenError,
            DatabaseOpenOptions,
            WorkerStartError,
        )

        t = self.target
        db = t.db
        assert db is not None
        self.fresh = t.input is not None and not db.exists() and not db.with_suffix(".id0").exists()
        attached = None if self.opts.no_server else self._find_gui()
        if attached is not None:
            self.handle = DatabaseHandle.attach(attached)
            self.gui = True
            return self
        s = self.spec
        options = DatabaseOpenOptions(
            output_database=str(db) if t.input is not None else None,
            # Analysis starts when a command first needs it (ensure), so that
            # earlier steps of a chain can influence it.
            auto_analysis=False,
            startup_timeout=600.0,
            keepalive=self.opts.keepalive,
            processor=s.processor if self.fresh else None,
            file_type=s.file_type if self.fresh else None,
            image_base=s.image_base if self.fresh else None,
            entry_point=s.entry_point if self.fresh else None,
            compiler=s.compiler if self.fresh else None,
            no_segmentation=s.no_segmentation if self.fresh else False,
            db_compression=s.db_compression,
            load_resources=s.load_resources if self.fresh else False,
            first_pass_directives=s.first_pass_directives,
            second_pass_directives=s.second_pass_directives,
            plugin_options=s.plugin_options,
            log_file=s.log_file,
            worker_cwd=str(Path.cwd()),
        )
        if self.fresh and not self.opts.quiet:
            self.diag("info", "LOAD", f"loading {t.input.name if t.input else db.name} ...")
        path = str(t.input if t.input is not None else db)
        try:
            self.handle = self._open_with_retry(DatabaseHandle, path, options)
        except DatabaseBusyError as error:
            raise IdaxError(Exit.LOCKED, f"database locked: {error}", "LOCKED")
        except WorkerStartError as error:
            raise IdaxError(Exit.LOAD, f"load failure: {_tail(str(error))}", "LOAD")
        except DatabaseOpenError as error:
            msg = str(error)
            if "newer" in msg.lower() or "corrupt" in msg.lower():
                raise IdaxError(Exit.CORRUPT, msg, "CORRUPT")
            raise IdaxError(Exit.LOAD, f"cannot open database: {_tail(msg)}", "LOAD")
        if self.fresh:
            if s.post_load:
                self.call("load.post", s.post_load, need="loaded")
            if self.opts.analysis != "none":
                self.call("lifecycle.mark", {"started": True}, need="loaded")
        return self

    def _open_with_retry(self, handle_cls: Any, path: str, options: Any) -> Any:
        """Open; when the owner is a managed worker that is draining (saving
        after its last lease), wait for it to release and open again."""
        from ida_nexus import DatabaseBusyError, find_database_owner, wait_database_released

        deadline = time.monotonic() + 120.0
        while True:
            try:
                return handle_cls.open(path, options=options)
            except DatabaseBusyError:
                owner = find_database_owner(path, output_database=options.output_database)
                if owner is None or not owner.managed or time.monotonic() > deadline:
                    raise
                wait_database_released(owner, timeout=max(1.0, deadline - time.monotonic()))

    def _find_gui(self) -> Any:
        """A GUI IDA (with the ida-nexus plugin) that has this input open."""
        from ida_nexus import InstanceState, discover_databases

        want = {str(p) for p in (self.target.input, self.target.db) if p}
        try:
            found = discover_databases()
        except Exception:
            return None
        for item in found:
            inst = item.instance
            if item.state is not InstanceState.READY or inst.backend != "gui":
                continue
            if inst.exe_path in want or inst.idb_path in want:
                return inst
        return None

    def close(self, *, save: bool = True) -> None:
        h, self.handle = self.handle, None
        if h is None:
            return
        instance = h.instance
        try:
            if self.target.temporary or self.opts.read_only or not save:
                if not self.gui:
                    try:
                        h.shutdown_database(save=False)
                    except Exception:
                        pass
            elif self.gui and self.dirty:
                try:
                    h.save_database()
                except Exception:
                    pass
        finally:
            try:
                h.close()
            except Exception:
                pass
        if instance.managed and not self.gui and self.opts.keepalive <= 0:
            # The worker saves and exits after its last lease: wait, so the
            # database is persisted (and unlocked) when icli returns.
            _wait_released(instance, timeout=600.0)
        if self.target.temporary and self.target.db is not None:
            shutil.rmtree(self.target.db.parent, ignore_errors=True)

    def save(self) -> None:
        if self.handle is not None and not self.opts.read_only and not self.target.temporary:
            self.handle.save_database()
            self.saved = True

    def __enter__(self) -> "Session":
        return self.open()

    def __exit__(self, *exc: Any) -> None:
        self.close(save=exc[0] is None)

    # -- analysis --------------------------------------------------------------------

    def state(self) -> str:
        return self.call("lifecycle.state", {}, need="loaded")["records"][0]["state"]

    def ensure(self, need: str) -> None:
        """Bring the database to the lifecycle state a command needs."""
        if need in (None, "none", "loaded") or self._ready:
            return
        poll = self.handle.poll_autoanalysis()
        if poll.get("complete"):
            if self.fresh and self.opts.analysis != "none":
                self._mark_analyzed()
        elif self.opts.analysis == "none":
            raise IdaxError(Exit.STATE, f"database is not {need} (and --analysis=none)", "STATE")
        else:
            self._wait()
        self._ready = not self.partial

    def _wait(self) -> None:
        from ida_nexus import RemoteError

        timeout = self.opts.analysis_timeout
        start = time.monotonic()
        if not self.opts.quiet:
            self.diag("info", "ANALYZE", "analysing ...")
        try:
            res = self.handle.wait_autoanalysis(timeout=timeout)
        except RemoteError as error:
            if "timeout" in error.code or "timed out" in str(error).lower():
                self.partial = True
                self.diag("warning", "TIMEOUT",
                          f"analysis stopped after {time.monotonic() - start:.0f}s; state is analyzing")
                return
            raise IdaxError(Exit.INTERNAL, f"analysis failed: {error}", "INTERR")
        if res.get("complete"):
            self._mark_analyzed()
            if not self.opts.quiet and self.opts.verbose:
                self.diag("info", "ANALYZE", f"analysed in {time.monotonic() - start:.1f}s")
        else:
            self.partial = True

    def _mark_analyzed(self) -> None:
        self.call("lifecycle.mark", {"started": True, "analyzed": True}, need="loaded")
        self.dirty = True

    # -- engine calls ------------------------------------------------------------------

    def call(self, op: str, params: dict | None = None, *, ctx: dict | None = None,
             prev: list[dict] | None = None, need: str = "analyzed",
             timeout: float | None = None) -> dict:
        from ida_nexus import DatabaseDisconnectedError, NexusConnectionError, RemoteError

        if self.handle is None:
            raise IdaxError(Exit.INTERNAL, "session is not open", "INTERR")
        self.ensure(need)
        request = json.dumps({"op": op, "params": params or {}, "ctx": ctx or {}, "prev": prev or []},
                             separators=(",", ":"))
        code = _BOOTSTRAP.format(root=_SRC_ROOT, digest=source_digest(), request=request)
        try:
            res = self.handle.execute_python(code, timeout=timeout or self.opts.exec_timeout,
                                             operation_label=f"icli {op}")
        except RemoteError as error:
            if "timeout" in error.code:
                raise IdaxError(Exit.TIMEOUT, f"{op}: timed out", "TIMEOUT")
            detail = error.details.get("traceback") if isinstance(error.details, dict) else None
            raise IdaxError(Exit.INTERNAL, f"{op}: {error}" + (f"\n{detail}" if detail and self.opts.verbose
                                                                else ""), "INTERR")
        except DatabaseDisconnectedError as error:
            raise IdaxError(Exit.INTERNAL, f"IDA process lost: {error}", "INTERR")
        except NexusConnectionError as error:
            raise IdaxError(Exit.INTERNAL, f"connection to IDA failed: {error}", "INTERR")
        out = res.get("result") or {}
        if self.opts.verbose >= 2:
            for stream in ("stdout", "stderr"):
                if res.get(stream):
                    sys.stderr.write(res[stream])
        if "error" in out:
            for w in out.get("warnings", []):
                self.diag(w.get("level", "warning"), w.get("code", ""), w.get("msg", ""))
            raise IdaxError.from_dict(out["error"])
        return out

    def execute(self, code: str, *, timeout: float | None = None, persist: bool = False,
                label: str = "icli exec") -> dict:
        """Raw ida-nexus execution (``icli exec`` semantics match ida-mcp)."""
        return self.handle.execute_python(code, timeout=timeout, persist_globals=persist,
                                          operation_label=label)


def _tail(text: str, n: int = 12) -> str:
    lines = text.strip().splitlines()
    return "\n".join(lines[-n:])


def _wait_released(instance: Any, timeout: float = 30.0) -> None:
    try:
        from ida_nexus import wait_database_released

        wait_database_released(instance, timeout=timeout)
    except Exception:
        time.sleep(0.2)
