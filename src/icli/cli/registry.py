"""Command registry and the per-invocation context handed to commands."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ClassVar

from ..errors import Exit, IdaxError, combine, usage
from ..lang import selector as psel
from .options import GlobalOptions
from .output import Emitter

GROUPS = [
    ("triage", "identify, info, loaders, processors"),
    ("analysis", "analyze, status"),
    ("query", "list, show, disasm, decompile, xrefs, callgraph, search, resolve"),
    ("edit", "rename, comment, type, func, make, patch, tag"),
    ("journal", "apply, log, undo"),
    ("knowledge", "sig, til, lumina, load"),
    ("output", "export"),
    ("compare", "diff, port"),
    ("automation", "do, batch, exec, ref, assert"),
    ("dynamic", "debug, trace"),
    ("storage", "db, cache, vault, serve"),
    ("meta", "config, schema, completion, legacy, help"),
]

COMMANDS: dict[str, "Command"] = {}


class Command:
    """One icli command.

    ``target``: "required" (first positional, or the default target),
    "none" (no database), or "optional".
    ``rest_min``: positionals that must remain after the target.
    ``needs``: lifecycle state required before running (loaded/analyzed/enriched).
    """

    name: ClassVar[str]
    group: ClassVar[str]
    summary: ClassVar[str] = ""
    target: ClassVar[str] = "required"
    rest_min: ClassVar[int] = 0
    needs: ClassVar[str] = "analyzed"
    raw_field: ClassVar[str | None] = None
    edits: ClassVar[bool] = False
    passthrough: ClassVar[bool] = False     # keep tokens after "--"
    subcommands: ClassVar[dict[str, str]] = {}
    # global option strings this command redefines for itself
    overrides: ClassVar[frozenset[str]] = frozenset()
    # options whose value is optional ("--bytes [N]"): flag -> (default, accepts(token))
    optional_values: ClassVar[dict[str, tuple[str, Callable[[str], bool]]]] = {}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target/selector", help="target and selectors")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def run(self, inv: "Invocation") -> int:
        raise NotImplementedError

    def help_text(self) -> str:
        from .manual import command_entry

        return command_entry(self.name)


def register(cls: type[Command]) -> type[Command]:
    COMMANDS[cls.name] = cls()
    return cls


def load_commands() -> None:
    if not COMMANDS:
        from . import commands  # noqa: F401  (registration)


# -- invocation --------------------------------------------------------------------


_stdin_cache: list[str] | None = None


def stdin_lines() -> list[str]:
    global _stdin_cache
    if _stdin_cache is None:
        _stdin_cache = [line.rstrip("\r\n") for line in sys.stdin] if not sys.stdin.closed else []
    return _stdin_cache


def lines_to_selectors(lines: list[str], origin: str) -> list[dict]:
    """Selector lines: JSON records (with ea/start/from/to) or selector text."""
    records: list[dict] = []
    out: list[dict] = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("{"):
            try:
                rec = json.loads(s)
            except json.JSONDecodeError as error:
                raise usage(f"{origin}:{i}: bad JSON record: {error}")
            if rec.get("_t") == "diag":
                continue
            records.append(rec)
            continue
        if "\t" in s:
            s = s.split("\t", 1)[0]
        out.append(psel.parse(s))
    if records:
        out.insert(0, {"op": "items", "items": records})
    return out


@dataclass
class Invocation:
    command: Command
    args: argparse.Namespace
    g: GlobalOptions
    emitter: Emitter
    argv: list[str] = field(default_factory=list)
    passthrough: list[str] = field(default_factory=list)
    session: Any = None            # provided by a chain (do/batch) or opened lazily
    chain: bool = False            # inside icli do: positionals carry no target
    prev: list[dict] = field(default_factory=list)
    status: int = 0
    produced: list[dict] = field(default_factory=list)
    _owns_session: bool = False
    target_spec: str | None = None

    # -- positionals ---------------------------------------------------------------

    def positionals(self, rest_min: int | None = None) -> list[str]:
        """The command's positionals after the target (opening nothing)."""
        items = list(getattr(self.args, "items", []) or [])
        if self.chain or self.command.target == "none":
            return items
        from .target import split_target

        spec, rest = split_target(items, minimum_rest=self.command.rest_min if rest_min is None else rest_min)
        self.target_spec = spec
        return rest

    def selectors(self, texts: list[str]) -> list[dict]:
        out: list[dict] = []
        for t in texts:
            if t == "-":
                out.extend(lines_to_selectors(stdin_lines(), "<stdin>"))
                continue
            if t.startswith("@") and len(t) > 1 and Path(t[1:]).is_file():
                out.extend(lines_to_selectors(Path(t[1:]).read_text().splitlines(), t[1:]))
                continue
            node = psel.parse(t)
            out.append(psel.replace(node, self._expand))
        return out

    def _expand(self, node: dict) -> dict | None:
        if node["op"] == "stdin":
            sels = lines_to_selectors(stdin_lines(), "<stdin>")
            return sels[0] if len(sels) == 1 else {"op": "union", "args": sels} if sels else \
                {"op": "items", "items": []}
        if node["op"] == "file":
            p = Path(node["path"])
            if not p.is_file():
                raise IdaxError(Exit.NOT_FOUND, f"@{node['path']}: no such file", "NOTFOUND")
            sels = lines_to_selectors(p.read_text().splitlines(), str(p))
            return {"op": "union", "args": sels} if sels else {"op": "items", "items": []}
        return None

    # -- database ------------------------------------------------------------------

    def open(self) -> Any:
        if self.session is not None:
            return self.session
        if self.target_spec is None:
            self.positionals()
        from .opening import open_session

        self.session = open_session(self.target_spec, self.g, self.emitter.diag)
        self._owns_session = True
        return self.session

    def engine_ctx(self, **extra: Any) -> dict:
        from .env import author

        ctx = {
            "addr": self.g.addr,
            "fields": self.emitter.wanted_fields(),
            "demangle": self.g.demangle,
            "strict": self.g.strict,
            "dry_run": self.g.dry_run,
            "read_only": self.g.read_only,
            "author": author(),
            "command": "icli " + " ".join(shlex.quote(a) for a in self.argv),
            "jobs": self.g.jobs,
        }
        ctx.update({k: v for k, v in extra.items() if v is not None})
        return ctx

    def call(self, op: str, params: dict | None = None, *, need: str | None = None,
             ctx: dict | None = None, emit: bool = True, timeout: float | None = None) -> dict:
        """Run an engine op and (by default) emit its records and warnings."""
        session = self.open()
        res = session.call(op, params or {}, ctx=self.engine_ctx(**(ctx or {})), prev=self.prev,
                           need=need or self.command.needs, timeout=timeout)
        for w in res.get("warnings", []):
            self.emitter.diag(w.get("level", "warning"), w.get("code", ""), w.get("msg", ""))
        if session.partial:
            self.set_status(Exit.PARTIAL)
        self.set_status(res.get("status", 0))
        if emit:
            self.emit(res.get("records", []))
            if res.get("raw"):
                self.emitter.raw(res["raw"])
        return res

    def emit(self, records: list[dict]) -> None:
        self.produced.extend(records)
        self.emitter.emit(records)

    def set_status(self, status: int) -> None:
        self.status = combine(self.status, int(status))

    def close(self, ok: bool) -> None:
        if self._owns_session and self.session is not None:
            self.session.close(save=ok)
            self.session = None


Handler = Callable[[Invocation], int]
