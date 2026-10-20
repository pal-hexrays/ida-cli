"""Automation: do, batch, exec, ref, assert."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import Any

from ...errors import Exit, IdaxError, combine, usage
from ..env import idausr
from ..output import Emitter
from ..registry import Command, Invocation, register, stdin_lines


# -- chains ------------------------------------------------------------------------------


def recipe_path(name: str) -> Path:
    for base in (idausr() / "icli" / "recipes", idausr() / "idx" / "recipes", Path.cwd()):
        for ext in (".icli", ".idx", ""):
            p = base / f"{name}{ext}"
            if p.is_file():
                return p
    raise IdaxError(Exit.NOT_FOUND, f"recipe @{name} not found in {idausr() / 'icli' / 'recipes'}", "NOTFOUND")


def recipe_steps(name: str, fields: dict[str, str]) -> list[list[str]]:
    from ...lang import template

    out = []
    for line in recipe_path(name).read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(shlex.split(template.render_inline(s, fields)))
    return out


def split_steps(tokens: list[str]) -> list[list[str]]:
    steps: list[list[str]] = [[]]
    for tok in tokens:
        if tok == "::":
            steps.append([])
        else:
            steps[-1].append(tok)
    return [s for s in steps if s]


def run_chain(inv: Invocation, steps: list[list[str]], *, keep_going: bool, no_save: bool,
              tag_steps: bool = False) -> int:
    """Run steps against one open database, left to right.  The database is
    saved once, at the end, and only if every step succeeded (or
    --keep-going); --no-save discards all changes."""
    from ..main import parse
    from ..options import GlobalOptions

    session = inv.open()
    status = 0
    failed = False
    prev: list[dict] = []
    base = {k: v for k, v in vars(inv.args).items() if k not in ("items", "sub", "keep_going", "no_save")}
    for index, argv in enumerate(steps, 1):
        if argv and argv[0] in ("do", "batch"):
            raise usage(f"step {index}: chains do not nest")
        try:
            cmd, ns, passthrough, tail = parse(argv)
            if cmd is None:
                raise usage(f"step {index}: empty step")
            merged = argparse.Namespace(**{**base, **vars(ns)})
            g = GlobalOptions.from_namespace(merged)
            emitter = Emitter(g.output, raw_field=cmd.raw_field)
            if tag_steps:
                emitter.tag = {"step": index}
            sub = Invocation(cmd, merged, g, emitter, argv=tail, passthrough=passthrough, session=session,
                             chain=True, prev=prev)
            try:
                st = combine(cmd.run(sub) or 0, sub.status)
            finally:
                emitter.close()
            prev = sub.produced
        except IdaxError as error:
            inv.emitter.diag("error", error.code, f"step {index} ({' '.join(argv[:2])}): {error.message}")
            st = error.status
        status = combine(status, st)
        if st not in (0, 1, 3):
            failed = True
            if not keep_going:
                break
    inv.chain_save = not no_save and (not failed or keep_going)
    return status


@register
class Do(Command):
    name = "do"
    group = "automation"
    summary = "open a database once and run steps (:: separated) left to right"
    passthrough = True
    needs = "loaded"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target [@recipe] [step...]")
        p.add_argument("--keep-going", action="store_true")
        p.add_argument("--no-save", action="store_true")

    def run(self, inv: Invocation) -> int:
        items = list(inv.args.items)
        if not items:
            raise usage("icli do: expected a target")
        inv.target_spec, rest = items[0], items[1:]
        session = inv.open()
        fields = {"input": session.target.input.name if session.target.input else session.target.db.stem,
                  "db": str(session.target.db), "name": (session.target.input or session.target.db).stem}
        steps: list[list[str]] = []
        for item in rest:
            if item.startswith("@"):
                steps.extend(recipe_steps(item[1:], fields))
            else:
                steps.append(shlex.split(item))
        for step in split_steps(inv.passthrough):
            if len(step) == 1 and step[0].startswith("@"):
                steps.extend(recipe_steps(step[0][1:], fields))
            else:
                steps.append(step)
        if not steps:
            raise usage("icli do: no steps (use: icli do TARGET -- step :: step, or @recipe)")
        return run_chain(inv, steps, keep_going=inv.args.keep_going, no_save=inv.args.no_save)


@register
class Batch(Command):
    name = "batch"
    group = "automation"
    summary = "like do, with steps read one per line from a file or standard input"
    needs = "loaded"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target [file|-]")
        p.add_argument("--keep-going", action="store_true")
        p.add_argument("--no-save", action="store_true")

    def run(self, inv: Invocation) -> int:
        items = list(inv.args.items)
        if not items:
            raise usage("icli batch: expected a target")
        inv.target_spec = items[0]
        source = items[1] if len(items) > 1 else "-"
        if source == "-":
            lines = stdin_lines()
        else:
            try:
                lines = Path(source).read_text().splitlines()
            except OSError as error:
                raise IdaxError(Exit.NOT_FOUND, f"{source}: {error.strerror}", "NOTFOUND")
        steps = [shlex.split(line) for line in lines if line.strip() and not line.strip().startswith("#")]
        if not steps:
            raise usage("icli batch: no steps")
        return run_chain(inv, steps, keep_going=inv.args.keep_going, no_save=inv.args.no_save, tag_steps=True)


# -- exec -----------------------------------------------------------------------------------


@register
class Exec(Command):
    name = "exec"
    group = "automation"
    summary = "run Python (ida-domain) or IDC against the database"
    passthrough = True
    overrides = frozenset({"--read-only"})

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="target [file.py|-]")
        p.add_argument("-c", dest="code", metavar="CODE")
        p.add_argument("--each", metavar="SEL")
        p.add_argument("--session", metavar="NAME")
        p.add_argument("--timeout", default="6m", metavar="DURATION")
        # same destination as the global option: absent must not reset it
        p.add_argument("--read-only", action="store_true", default=argparse.SUPPRESS)
        p.add_argument("--no-save", action="store_true")
        p.add_argument("--lang", choices=("py", "idc"), default="py")
        p.add_argument("--no-record-code", action="store_true")

    def run(self, inv: Invocation) -> int:
        from ...lang.values import parse_duration

        a = inv.args
        rest = inv.positionals(0)
        if a.code is not None:
            if rest:
                raise usage("icli exec: -c and a script file are exclusive")
            code, filename = a.code, "<command>"
        elif rest == ["-"] or (not rest and not sys.stdin.isatty()):
            code, filename = sys.stdin.read(), "<stdin>"
        elif len(rest) == 1:
            p = Path(rest[0])
            try:
                code, filename = p.read_text(), str(p.resolve())
            except OSError as error:
                raise IdaxError(Exit.NOT_FOUND, f"{rest[0]}: {error.strerror}", "NOTFOUND")
        else:
            raise usage("icli exec: expected -c CODE, a file, or - (standard input)")
        if a.lang == "py":
            try:
                compile(code, filename, "exec")
            except SyntaxError as error:
                sys.stderr.write(f"{filename}:{error.lineno}: {error.msg}\n")
                return Exit.SCRIPT
        if a.session:
            session = inv.open()
            if session.opts.keepalive <= 0 and not session.gui and not _served(session):
                raise usage("icli exec --session requires icli serve (the session lives in the server)")
        read_only = bool(getattr(a, "read_only", False)) or inv.g.read_only
        inv.g.read_only = read_only
        params: dict[str, Any] = {"code": code, "filename": filename, "args": inv.passthrough,
                                  "each": inv.selectors([a.each]) if a.each else None, "session": a.session,
                                  "lang": a.lang, "no_save": a.no_save, "record_code": not a.no_record_code}
        res = inv.call("exec", params, emit=False, timeout=parse_duration(a.timeout),
                       ctx={"read_only": read_only})
        extra = res.get("extra") or {}
        records = res.get("records", [])
        if inv.emitter.format == "json":
            inv.emitter.extra = {"stdout": extra.get("stdout", ""), "stderr": extra.get("stderr", "")}
        else:
            for stream in ("stdout", "stderr"):
                if extra.get(stream):
                    sys.stderr.write(extra[stream])
        inv.emit(records)
        if inv.session is not None and records is not None:
            inv.session.dirty = True
        return int(res.get("status", 0))


def _served(session: Any) -> bool:
    """Whether the database lives in a long-lived worker (icli serve)."""
    from ..serve import is_served

    return is_served(session)


# -- ref ------------------------------------------------------------------------------------


@register
class Ref(Command):
    name = "ref"
    group = "automation"
    summary = "search the ida-domain API reference (offline, no target)"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="query")
        p.add_argument("-n", type=int, default=5, metavar="N")
        p.add_argument("--full", action="store_true")

    def run(self, inv: Invocation) -> int:
        from ..reference import search

        query = " ".join(inv.args.items).strip()
        if not query:
            raise usage("icli ref: expected a query")
        hits = search(query, inv.args.n, full=inv.args.full)
        if inv.emitter.format == "text" and not inv.g.output.template:
            for h in hits:
                sys.stdout.write(f"{h['kind']} {h['signature']}\n")
                doc = h["doc"] if inv.args.full else (h["doc"].strip().splitlines() or [""])[0]
                if doc:
                    sys.stdout.write(f"    {doc}\n" if not inv.args.full else _indent(doc))
                if h.get("example"):
                    sys.stdout.write(_indent(h["example"], "    | "))
                sys.stdout.write(f"    ({h['source']})\n\n")
            if not hits:
                return Exit.NEGATIVE
            return 0
        inv.emit(hits)
        return 0 if hits else Exit.NEGATIVE


def _indent(text: str, prefix: str = "    ") -> str:
    return "".join(prefix + line + "\n" for line in text.rstrip().splitlines())


# -- assert -----------------------------------------------------------------------------------


@register
class Assert(Command):
    name = "assert"
    group = "automation"
    summary = "check the size of a selection; exit 1 (and print offenders) if it fails"
    rest_min = 2

    def run(self, inv: Invocation) -> int:
        rest = inv.positionals()
        if len(rest) < 2:
            raise usage("icli assert: expected a selector and a condition such as '<= 3'")
        sel, cond = rest[:-1], rest[-1]
        import re

        if not re.match(r"^\s*(==|!=|<=|>=|<|>)\s*\d+\s*$", cond):
            raise usage(f"icli assert: bad condition {cond!r}: expected (==|!=|<|<=|>|>=) N")
        res = inv.call("assert", {"selectors": inv.selectors(sel), "cond": cond})
        return Exit.NEGATIVE if res.get("records") else 0
