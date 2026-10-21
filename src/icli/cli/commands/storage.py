"""Storage: db, cache, vault, serve."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from ...errors import Exit, IcliError, usage
from ...lang.values import parse_duration, parse_size
from .. import cache
from ..frozen import self_command
from ..registry import Command, Invocation, register


def _db_path(spec: str) -> Path:
    p = Path(spec).expanduser()
    if p.suffix not in (".i64", ".idb"):
        raise usage(f"{spec}: expected a database (.i64/.idb)")
    if not p.exists() and not p.with_suffix(".id0").exists():
        raise IcliError(Exit.NOT_FOUND, f"{spec}: database not found", "NOTFOUND")
    return p.resolve()


def _components(db: Path) -> list[Path]:
    return [db.with_suffix(s) for s in (".id0", ".id1", ".id2", ".nam", ".til") if db.with_suffix(s).exists()]


@register
class Db(Command):
    name = "db"
    group = "storage"
    summary = "database paths, creation, packing, upgrade, checks, handles, copies, locks"
    target = "optional"
    subcommands = {"path": "print the database path (creates nothing)", "create": "load and analyse into a file",
                   "pack": "pack components into one .i64", "unpack": "unpack an .i64 into its components",
                   "upgrade": "convert an old .idb to .i64", "check": "verify b-tree integrity",
                   "gc": "compact the b-tree", "tag": "register a handle usable as @name",
                   "copy": "copy safely while in use", "unlock": "remove a stale lock"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        if sub in ("create", "upgrade"):
            p.add_argument("-o", dest="output", metavar="FILE", required=sub == "create")
        if sub == "pack":
            p.add_argument("--mode", choices=("compress", "pack"), default="compress")
        if sub == "unlock":
            p.add_argument("--force", action="store_true")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        sub = a.sub
        items = list(a.items)
        handler = getattr(self, f"do_{sub}")
        return handler(inv, items)

    def do_path(self, inv: Invocation, items: list[str]) -> int:
        from ..target import resolve, split_target

        spec, _ = split_target(items)
        t = resolve(spec, inv.g.load, db=inv.g.db, create=False)
        inv.emit([{"_t": "db", "db": str(t.db), "input": str(t.input) if t.input else None, "key": t.key,
                   "exists": t.db.exists() if t.db else False}])
        return 0

    def do_create(self, inv: Invocation, items: list[str]) -> int:
        if len(items) != 1:
            raise usage("icli db create: expected one input file")
        out = Path(inv.args.output).expanduser().resolve()
        if out.exists():
            raise IcliError(Exit.CONFLICT, f"{out}: already exists", "CONFLICT")
        inv.g.db = str(out)
        inv.target_spec = items[0]
        session = inv.open()
        session.ensure("analyzed")
        inv.emit([{"_t": "db", "db": str(out), "input": str(session.target.input), "state": session.state()}])
        return 0

    def do_pack(self, inv: Invocation, items: list[str]) -> int:
        from ..local import local_database

        db = _db_path(self._one(items, "pack"))
        flag = "-P+" if inv.args.mode == "compress" else "-P"
        with local_database(db, flag):
            pass
        inv.emit([{"_t": "db", "db": str(db), "packed": db.exists(), "mode": inv.args.mode,
                   "components": [p.name for p in _components(db)]}])
        return 0

    def do_unpack(self, inv: Invocation, items: list[str]) -> int:
        from ..local import local_database

        db = _db_path(self._one(items, "unpack"))
        with local_database(db, "-P-"):
            pass
        comps = _components(db)
        if not comps:
            raise IcliError(Exit.INTERNAL, f"{db}: unpacking produced no components", "INTERR")
        inv.emit([{"_t": "db", "db": str(db), "components": [str(p) for p in comps]}])
        return 0

    def do_upgrade(self, inv: Invocation, items: list[str]) -> int:
        from ..local import upgrade_idb

        old = _db_path(self._one(items, "upgrade"))
        out = Path(inv.args.output).expanduser().resolve() if inv.args.output else None
        if old.suffix == ".i64":
            inv.emit([{"_t": "db", "db": str(old), "status": "unchanged"}])
            return 0
        if out is not None and out.exists():
            raise IcliError(Exit.CONFLICT, f"{out}: already exists", "CONFLICT")
        result = upgrade_idb(old, out)
        inv.emit([{"_t": "db", "db": str(result), "from": str(old), "status": "upgraded"}])
        return 0

    def do_check(self, inv: Invocation, items: list[str]) -> int:
        from ida_nexus import probe_database_state

        from ..local import local_database

        db = _db_path(self._one(items, "check"))
        state = probe_database_state(str(db))
        rec = {"_t": "check", "db": str(db), "state": state["state"]}
        if state["state"] == "in_use":
            raise IcliError(Exit.LOCKED, f"{db}: in use by another process", "LOCKED")
        if state["state"] == "crashed":
            rec["ok"] = False
            inv.emit([rec])
            return Exit.CORRUPT
        try:
            with local_database(db, "", save=False):
                pass
            rec["ok"] = True
        except IcliError as error:
            rec.update({"ok": False, "error": error.message})
            inv.emit([rec])
            return Exit.CORRUPT
        inv.emit([rec])
        return 0

    def do_gc(self, inv: Invocation, items: list[str]) -> int:
        from ..local import local_database

        db = _db_path(self._one(items, "gc"))
        before = cache.db_size(db)
        with local_database(db, "-P+"):
            import ida_loader

            ida_loader.save_database(str(db), ida_loader.DBFL_COMP)
        inv.emit([{"_t": "db", "db": str(db), "size_before": before, "size_after": cache.db_size(db)}])
        return 0

    def do_tag(self, inv: Invocation, items: list[str]) -> int:
        if len(items) != 2:
            raise usage("icli db tag: expected NAME TARGET")
        name, target = items
        if not name.isidentifier():
            raise usage(f"icli db tag: bad handle name {name!r}")
        p = Path(target).expanduser()
        if not target.startswith("vault://") and not p.exists():
            raise IcliError(Exit.NOT_FOUND, f"{target}: no such file", "NOTFOUND")
        resolved = target if target.startswith("vault://") else str(p.resolve())
        cache.set_handle(name, resolved)
        inv.emit([{"_t": "handle", "name": f"@{name}", "target": resolved}])
        return 0

    def do_copy(self, inv: Invocation, items: list[str]) -> int:
        from ida_nexus import DatabaseHandle, find_database_owner

        if len(items) != 2:
            raise usage("icli db copy: expected SRC DST")
        src = _db_path(items[0])
        dst = Path(items[1]).expanduser().resolve()
        if dst.is_dir():
            dst = dst / src.name
        owner = find_database_owner(str(src))
        if owner is not None:
            with DatabaseHandle.attach(owner) as h:  # a read lock: save, copy while held
                h.save_database()
                shutil.copy2(src, dst)
        else:
            if not src.exists():
                raise IcliError(Exit.LOCKED, f"{src}: only unpacked components exist (crashed or open?)", "LOCKED")
            shutil.copy2(src, dst)
        inv.emit([{"_t": "db", "db": str(dst), "from": str(src), "size": dst.stat().st_size}])
        return 0

    def do_unlock(self, inv: Invocation, items: list[str]) -> int:
        from ida_nexus import find_database_owner, probe_database_state, wait_database_released

        db = _db_path(self._one(items, "unlock"))
        owner = find_database_owner(str(db))
        rec = {"_t": "unlock", "db": str(db)}
        if owner is not None:
            alive = _pid_alive(owner.pid)
            if alive and not inv.args.force:
                raise IcliError(Exit.LOCKED, f"{db}: held by live process {owner.pid} (use --force)", "LOCKED")
            if alive:
                os.kill(owner.pid, signal.SIGTERM)
                wait_database_released(owner, timeout=30)
            rec["holder"] = owner.pid
        state = probe_database_state(str(db))
        rec["state"] = state["state"]
        inv.emit([rec])
        return 0

    @staticmethod
    def _one(items: list[str], sub: str) -> str:
        if len(items) != 1:
            raise usage(f"icli db {sub}: expected one database")
        return items[0]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


@register
class Cache(Command):
    name = "cache"
    group = "storage"
    summary = "inspect and maintain the database cache"
    target = "optional"
    subcommands = {"ls": "list cached databases", "rm": "remove a target's cached database",
                   "key": "print a target's cache key", "prune": "remove old, large or orphaned entries"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        if sub == "prune":
            p.add_argument("--older-than", metavar="DURATION")
            p.add_argument("--max-size", metavar="SIZE")
            p.add_argument("--orphans", action="store_true")

    def run(self, inv: Invocation) -> int:
        from ..target import resolve

        sub = inv.args.sub
        items = inv.args.items
        if sub == "ls":
            inv.emit([{"_t": "cache", "key": e["key"], "input": e["input"], "db": e["db"], "size": e["size"],
                       "exists": e["exists"], "accessed": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                         time.gmtime(e["accessed"] or 0))}
                      for e in cache.entries()])
            return 0
        if sub in ("rm", "key"):
            if len(items) != 1:
                raise usage(f"icli cache {sub}: expected one target")
            t = resolve(items[0], inv.g.load, create=False)
            if t.key is None:
                raise usage(f"{items[0]}: not a cached target (a database, or --db given)")
            if sub == "key":
                inv.emit([{"_t": "cache", "key": t.key, "db": str(t.db), "input": str(t.input)}])
                return 0
            self._remove(t.db, t.key)
            inv.emit([{"_t": "cache", "key": t.key, "removed": True}])
            return 0
        if sub == "prune":
            return self._prune(inv)
        raise usage(f"icli cache: unknown subcommand {sub}")

    @staticmethod
    def _remove(db: Path, key: str) -> None:
        from ida_nexus import find_database_owner

        if find_database_owner(str(db)) is not None:
            raise IcliError(Exit.LOCKED, f"{db}: in use", "LOCKED")
        cache.remove_db_files(db)
        cache.forget(key)

    def _prune(self, inv: Invocation) -> int:
        a = inv.args
        if not (a.older_than or a.max_size or a.orphans):
            raise usage("icli cache prune: give --older-than, --max-size and/or --orphans")
        entries = cache.entries()
        now = time.time()
        victims: dict[str, dict] = {}
        if a.older_than:
            age = parse_duration(a.older_than)
            victims.update({e["key"]: e for e in entries if now - (e["accessed"] or 0) > age})
        if a.orphans:
            for e in entries:
                if not e["exists"] or not Path(e["input"] or "").exists():
                    victims[e["key"]] = e
        if a.max_size:
            limit = parse_size(a.max_size)
            total = sum(e["size"] for e in entries if e["key"] not in victims)
            for e in sorted((e for e in entries if e["key"] not in victims), key=lambda e: e["accessed"] or 0):
                if total <= limit:
                    break
                victims[e["key"]] = e
                total -= e["size"]
        out = []
        for key, e in victims.items():
            try:
                self._remove(Path(e["db"]), key)
                out.append({"_t": "cache", "key": key, "input": e["input"], "removed": True, "size": e["size"]})
            except IcliError as error:
                out.append({"_t": "cache", "key": key, "removed": False, "error": error.message})
        inv.emit(out)
        return 0


# -- vault (IDA Teams, through hv) -------------------------------------------------------------


def _hv() -> list[str]:
    from ..env import env, idadir

    d = idadir()
    override = env("HV")  # ICLI_HV: an alternative hv binary
    tool = Path(override) if override else (d / "hv" if d else None)
    if tool is None or not tool.exists():
        raise IcliError(Exit.LICENSE, "hv (IDA Teams client) not found in the IDA installation", "NOTOOL")
    cmd = [str(tool)]
    for flag, var in (("-h", "VAULT_HOST"), ("-u", "VAULT_USER"), ("-p", "VAULT_PASS"), ("-s", "VAULT_SITE")):
        if os.environ.get(var):
            cmd.append(f"{flag}{os.environ[var]}")
    return cmd


def run_hv(args: list[str], *, site: str | None = None) -> subprocess.CompletedProcess:
    cmd = _hv()
    if site:
        cmd = [c for c in cmd if not c.startswith("-s")] + [f"-s{site}"]
    res = subprocess.run(cmd + args, capture_output=True, text=True)
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip()
        low = msg.lower()
        status = Exit.NETWORK if any(w in low for w in ("connect", "network", "host", "timed out", "refused",
                                                         "login", "password", "unreachable")) else Exit.USAGE
        raise IcliError(status, f"hv {' '.join(args[:2])}: {msg[-800:] or f'exit {res.returncode}'}", "VAULT")
    return res


VAULT_STRATEGIES = {"ours": "local", "theirs": "remote", "fail": "auto", "manual": "manual"}


@register
class Vault(Command):
    name = "vault"
    group = "storage"
    summary = "IDA Teams, mirroring hv(1); non-interactive merge"
    target = "optional"
    subcommands = {"sync": "pull from the vault", "checkout": "check a database out for editing",
                   "add": "add files", "commit": "push changes", "revert": "revert checked-out files",
                   "diff": "compare file content", "log": "file history", "info": "vault info",
                   "merge": "three-way database merge, conflicts as records"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        if sub == "commit":
            p.add_argument("-m", "--message", required=True)
            p.add_argument("--force", action="store_true")
        if sub == "merge":
            p.add_argument("--strategy", choices=("ours", "theirs", "fail"), default="fail")

    def run(self, inv: Invocation) -> int:
        from ..vault import local_path, parse_spec

        a = inv.args
        sub = a.sub
        items = list(a.items)
        if sub == "info":
            res = run_hv(["info"])
            inv.emit([{"_t": "vault", "info": res.stdout.strip()}])
            return 0
        if not items and sub not in ("sync",):
            raise usage(f"icli vault {sub}: expected a path or vault:// target")
        specs = [parse_spec(x) if x.startswith("vault://") else {"site": None, "path": x, "rev": None}
                 for x in items]
        out = []
        for s in specs:
            site, path, rev = s["site"], s["path"], s["rev"]
            if sub == "sync":
                res = run_hv(["sync", "-s", f"{path}#{rev}" if rev else path] if path else ["sync", "-s"], site=site)
            elif sub == "checkout":
                run_hv(["sync", "-s", f"{path}#{rev}" if rev else path], site=site)
                res = run_hv(["edit", "-s", path], site=site)
            elif sub == "add":
                res = run_hv(["add", "-s", path], site=site)
            elif sub == "commit":
                if not a.force:
                    self._refuse_analyzing(inv, s)
                res = run_hv(["commit", "1", a.message], site=site)  # hv commit WORKLIST DESCRIPTION
            elif sub == "revert":
                res = run_hv(["revert", "-s", path], site=site)
            elif sub == "diff":
                res = run_hv(["diff", f"{path}#{rev}" if rev else path], site=site)
            elif sub == "log":
                res = run_hv(["history", path], site=site)
                for line in res.stdout.splitlines():
                    if line.strip():
                        out.append({"_t": "vault_log", "path": path, "entry": line.strip()})
                continue
            elif sub == "merge":
                res = run_hv(["resolve", VAULT_STRATEGIES[a.strategy], path], site=site)
                conflicts = [ln.strip() for ln in res.stdout.splitlines() if "conflict" in ln.lower()]
                for c in conflicts:
                    out.append({"_t": "conflict", "path": path, "detail": c, "strategy": a.strategy})
                if conflicts and a.strategy == "fail":
                    inv.emit(out)
                    return Exit.CONFLICT
                continue
            else:
                raise usage(f"icli vault: unknown subcommand {sub}")
            out.append({"_t": "vault", "op": sub, "path": path, "local": str(local_path(s)) if path else None,
                        "output": res.stdout.strip()})
        inv.emit(out)
        return 0

    def _refuse_analyzing(self, inv: Invocation, spec: dict) -> None:
        from ..vault import local_path

        p = local_path(spec)
        if p is None or not p.exists() or p.suffix != ".i64":
            return
        inv.target_spec = str(p)
        session = inv.open()
        if session.state() == "analyzing":
            raise IcliError(Exit.STATE, f"{p}: analysis incomplete; commit with --force", "STATE")


@register
class Serve(Command):
    name = "serve"
    group = "storage"
    summary = "keep databases open; forward icli commands to them (and MCP)"
    needs = "loaded"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target")
        p.add_argument("--detach", action="store_true")
        p.add_argument("--idle-timeout", default="30m", metavar="DURATION")
        p.add_argument("--save-every", metavar="DURATION")
        p.add_argument("--listen", metavar="HOST:PORT", help="also listen on TCP (requires --token-file)")
        p.add_argument("--token-file", metavar="FILE")
        p.add_argument("--stop", action="store_true")
        p.add_argument("--mcp", metavar="stdio|http:HOST:PORT")

    def run(self, inv: Invocation) -> int:
        from .. import serve as srv
        from ..opening import open_session, resolve_target

        a = inv.args
        if not a.items:
            raise usage("icli serve: expected target(s)")
        targets = [resolve_target(x, inv.g) for x in a.items]
        if a.stop:
            out = []
            for t in targets:
                out.append({"_t": "serve", "db": str(t.db), "stopped": srv.stop_server(t.db)})
            inv.emit(out)
            return 0 if all(x["stopped"] for x in out) else Exit.NEGATIVE
        for t in targets:
            rec = srv.server_for(t.db)
            if rec is not None:
                raise IcliError(Exit.LOCKED, f"{t.db}: already served by pid {rec['pid']}", "LOCKED")
        if a.listen and not a.token_file:
            raise usage("icli serve --listen requires --token-file")
        token = Path(a.token_file).read_text().strip() if a.token_file else None
        if a.detach:
            return self._detach(inv, targets)
        sessions = []
        for spec in a.items:
            s = open_session(spec, inv.g, inv.emitter.diag)
            s.ensure("analyzed")
            sessions.append(s)
        return srv.serve(sessions, idle_timeout=parse_duration(a.idle_timeout) if a.idle_timeout else None,
                         save_every=parse_duration(a.save_every) if a.save_every else None, listen=a.listen,
                         token=token, mcp=a.mcp, diag=inv.emitter.diag)

    def _detach(self, inv: Invocation, targets: list) -> int:
        from .. import serve as srv

        argv = [a for a in sys.argv[1:] if a != "--detach"]
        log = (srv.runtime_dir() / f"serve-{os.getpid()}.log")
        srv.runtime_dir().mkdir(parents=True, exist_ok=True)
        with log.open("ab") as fh:
            proc = subprocess.Popen([*self_command(), *argv], stdin=subprocess.DEVNULL, stdout=fh,
                                    stderr=fh, start_new_session=True, cwd=os.getcwd())
        deadline = time.time() + 900
        while time.time() < deadline:
            if all(srv.server_for(t.db) for t in targets):
                inv.emit([{"_t": "serve", "pid": proc.pid, "db": str(t.db), "socket": str(srv.socket_path(t.db))}
                          for t in targets])
                return 0
            if proc.poll() is not None:
                raise IcliError(Exit.LOAD, f"server exited with {proc.returncode}; see {log}", "SERVE")
            time.sleep(0.2)
        raise IcliError(Exit.TIMEOUT, "server did not start in time", "TIMEOUT")
