"""``icli serve``: keep databases open and answer forwarded commands.

The server holds one ida-nexus lease per served database (so the idalib
worker, its analysis and any ``exec --session`` namespace stay alive) and
listens on a Unix socket, ``$XDG_RUNTIME_DIR/icli/<key>.sock`` (and,
optionally, TCP with a bearer token).  Every icli command whose target is
served is forwarded whole -- argv, working directory, standard input -- and
runs in the server against the already open session.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import signal
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any

from ..errors import Exit, IcliError
from .env import env, runtime_dir

SERVED: dict[str, Any] = {}
"""Sessions held by this process when it is a server, by database path."""

_lock = threading.Lock()
_activity = [time.time()]


def _key(db: str | Path) -> str:
    return hashlib.sha256(str(Path(db).resolve()).encode()).hexdigest()[:16]


def state_path(db: str | Path) -> Path:
    return runtime_dir() / f"{_key(db)}.json"


def socket_path(db: str | Path) -> Path:
    return runtime_dir() / f"{_key(db)}.sock"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def server_for(db: str | Path) -> dict | None:
    """The live server record for a database, if any."""
    p = state_path(db)
    try:
        rec = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    if not _alive(int(rec.get("pid", 0))):
        for stale in (p, socket_path(db)):
            with contextlib.suppress(OSError):
                stale.unlink()
        return None
    return rec


def is_served(session: Any) -> bool:
    db = session.target.db
    return db is not None and (str(db) in SERVED or server_for(db) is not None)


# -- client side ---------------------------------------------------------------------------


def _send(address: str, request: dict, token: str | None) -> dict:
    data = (json.dumps(request) + "\n").encode()
    if address.startswith("tcp://"):
        host, _, port = address[6:].rpartition(":")
        sock = socket.create_connection((host or "127.0.0.1", int(port)), timeout=30)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(address)
    sock.settimeout(None)
    with sock:
        if token:
            request["token"] = token
            data = (json.dumps(request) + "\n").encode()
        sock.sendall(data)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
    if not buf:
        raise IcliError(Exit.TIMEOUT, f"server at {address} closed the connection", "SERVER")
    return json.loads(buf)


def forward(address: str, argv: list[str], *, token: str | None = None) -> int:
    """Run a command line in the server; replay its output here."""
    stdin = ""
    if not sys.stdin.isatty() and _wants_stdin(argv):
        stdin = sys.stdin.read()
    req = {"argv": argv, "cwd": os.getcwd(), "stdin": stdin, "tty": sys.stdout.isatty(),
           "env": {k: v for k, v in os.environ.items() if k.startswith("ICLI_") and k != "ICLI_SOCKET"}}
    try:
        res = _send(address, req, token)
    except OSError as error:
        raise IcliError(Exit.TIMEOUT, f"cannot reach icli server at {address}: {error}", "SERVER")
    sys.stdout.write(res.get("out", ""))
    sys.stdout.flush()
    sys.stderr.write(res.get("err", ""))
    return int(res.get("code", Exit.INTERNAL))


def _wants_stdin(argv: list[str]) -> bool:
    return "-" in argv or any(a in ("batch", "apply", "exec", "rename") for a in argv[:3])


def maybe_forward(spec: str | None, g: Any, argv: list[str]) -> int | None:
    """Forward the command when its target is served; ``None`` otherwise."""
    if SERVED or g.no_server:
        return None
    explicit = env("SOCKET")
    if explicit:
        token = env("TOKEN")
        tf = env("TOKEN_FILE")
        if tf and not token:
            token = Path(tf).read_text().strip()
        return forward(explicit if explicit.startswith("tcp://") else str(Path(explicit)), argv, token=token)
    if spec is None:
        return None
    try:
        from .opening import resolve_target

        target = resolve_target(spec, g)
    except IcliError:
        return None
    if target.db is None or target.temporary:
        return None
    rec = server_for(target.db)
    if rec is None:
        return None
    return forward(rec["socket"], argv, token=None)


# -- server side ---------------------------------------------------------------------------


def _run_forwarded(req: dict) -> dict:
    from . import registry
    from .main import main as icli_main

    argv = list(req.get("argv") or [])
    if req.get("tty") and not any(a in ("-f", "--format") or a.startswith("--format=") for a in argv):
        argv = ["-f", "text", *argv]
    out, err = io.StringIO(), io.StringIO()
    saved_env = {}
    for k, v in (req.get("env") or {}).items():
        saved_env[k] = os.environ.get(k)
        os.environ[k] = v
    old_cwd = os.getcwd()
    old_stdin = sys.stdin
    try:
        os.chdir(req.get("cwd") or old_cwd)
        sys.stdin = io.StringIO(req.get("stdin") or "")
        registry._stdin_cache = None  # noqa: SLF001 - per-request standard input
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = icli_main(argv)
            except SystemExit as e:
                code = int(e.code or 0)
    finally:
        sys.stdin = old_stdin
        registry._stdin_cache = None  # noqa: SLF001
        os.chdir(old_cwd)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return {"out": out.getvalue(), "err": err.getvalue(), "code": code}


class _Handler(socketserver.StreamRequestHandler):
    token: str | None = None

    def handle(self) -> None:
        line = self.rfile.readline()
        if not line:
            return
        try:
            req = json.loads(line)
            if self.token is not None and req.get("token") != self.token:
                res = {"out": "", "err": "icli: error: bad or missing token\n", "code": int(Exit.USAGE)}
            else:
                with _lock:
                    _activity[0] = time.time()
                    res = _run_forwarded(req)
                    _activity[0] = time.time()
        except Exception as error:  # noqa: BLE001 - reported to the client
            res = {"out": "", "err": f"icli: error: server: {error}\n", "code": int(Exit.INTERNAL)}
        self.wfile.write((json.dumps(res) + "\n").encode())


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(sessions: list[Any], *, idle_timeout: float | None, save_every: float | None,
          listen: str | None, token: str | None, mcp: str | None, diag: Any) -> int:
    runtime_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(runtime_dir(), 0o700)
    servers: list[socketserver.BaseServer] = []
    states: list[Path] = []
    stop = threading.Event()
    for s in sessions:
        db = s.target.db
        SERVED[str(db)] = s
        sp = socket_path(db)
        with contextlib.suppress(OSError):
            sp.unlink()
        srv = _UnixServer(str(sp), _Handler)
        os.chmod(sp, 0o600)
        servers.append(srv)
        st = state_path(db)
        st.write_text(json.dumps({"pid": os.getpid(), "db": str(db), "socket": str(sp),
                                  "input": str(s.target.input) if s.target.input else None,
                                  "started": time.time(), "listen": listen}))
        states.append(st)
    if listen:
        host, _, port = listen.rpartition(":")
        handler = type("_TokenHandler", (_Handler,), {"token": token})
        tcp = _TCPServer((host or "127.0.0.1", int(port)), handler)
        servers.append(tcp)
    threads = [threading.Thread(target=srv.serve_forever, daemon=True) for srv in servers]
    for t in threads:
        t.start()

    def shutdown(*_: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    diag("info", "SERVE", f"serving {', '.join(str(s.target.db) for s in sessions)} (pid {os.getpid()})")
    if mcp:
        threading.Thread(target=_run_mcp, args=(mcp, sessions, stop, diag), daemon=True).start()
    last_save = time.time()
    try:
        while not stop.wait(0.5):
            now = time.time()
            if idle_timeout and now - _activity[0] > idle_timeout:
                diag("info", "SERVE", "idle timeout")
                break
            if save_every and now - last_save > save_every:
                with _lock:
                    for s in sessions:
                        with contextlib.suppress(Exception):
                            s.save()
                last_save = now
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
        with _lock:
            for s in sessions:
                SERVED.pop(str(s.target.db), None)
                s.close(save=True)
        for st in states:
            with contextlib.suppress(OSError):
                st.unlink()
        for s in sessions:
            with contextlib.suppress(OSError):
                socket_path(s.target.db).unlink()
    return 0


def _run_mcp(spec: str, sessions: list[Any], stop: threading.Event, diag: Any) -> None:
    """Expose the served databases through the official ida-mcp tool set;
    it attaches to the same ida-nexus workers."""
    try:
        from ida_mcp import mcp as ida_mcp
    except ImportError:
        diag("error", "MCP", "--mcp needs the ida-mcp package")
        stop.set()
        return
    try:
        if spec == "stdio":
            ida_mcp.serve_stdio()
        elif spec.startswith("http:"):
            host, _, port = spec[5:].rpartition(":")
            ida_mcp.serve_http(host or "127.0.0.1", int(port))
        else:
            diag("error", "MCP", f"--mcp {spec}: expected stdio or http:HOST:PORT")
    finally:
        stop.set()


def stop_server(db: str | Path, timeout: float = 60.0) -> bool:
    rec = server_for(db)
    if rec is None:
        return False
    os.kill(int(rec["pid"]), signal.SIGTERM)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _alive(int(rec["pid"])):
            return True
        time.sleep(0.1)
    return False
