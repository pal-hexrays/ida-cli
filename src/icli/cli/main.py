"""icli entry point: argument parsing, dispatch, exit statuses."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from typing import Sequence

from ..errors import Exit, IdaxError, combine, usage
from .options import GlobalOptions, add_global_options, add_load_options
from .output import Emitter, OutputOptions
from .registry import COMMANDS, GROUPS, Command, Invocation, load_commands


class _Parser(argparse.ArgumentParser):
    """argparse with usage errors raised as status 2 instead of exiting."""

    def error(self, message: str):  # type: ignore[override]
        raise usage(f"{self.prog}: {message}")


def _global_parser() -> _Parser:
    p = _Parser(prog="icli", add_help=False)
    add_global_options(p)
    add_load_options(p)
    p.add_argument("-h", "--help", action="store_true", default=argparse.SUPPRESS)
    p.add_argument("--version", action="store_true", default=argparse.SUPPRESS)
    return p


def first_positional(argv: Sequence[str], parser: argparse.ArgumentParser) -> int:
    """Index of the first positional token, skipping options and their values."""
    actions = parser._option_string_actions  # noqa: SLF001 - argparse has no public equivalent
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return i + 1 if i + 1 < len(argv) else len(argv)
        if tok.startswith("-") and tok != "-":
            name = tok.split("=", 1)[0]
            action = actions.get(name)
            if action is None and not tok.startswith("--") and len(tok) > 2:
                # bundled short options: -qv, -j8, -fjson
                action = actions.get(tok[:2])
                if action is not None and action.nargs != 0:
                    i += 1
                    continue
                i += 1
                continue
            if action is not None and action.nargs != 0 and "=" not in tok:
                i += 2
            else:
                i += 1
            continue
        return i
    return len(argv)


def command_parser(cmd: Command, sub: str | None = None) -> _Parser:
    prog = f"icli {cmd.name}" + (f" {sub}" if sub else "")
    p = _Parser(prog=prog, description=cmd.summary, formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog=cmd.help_text() or None)
    if sub is None:
        cmd.configure(p)
    else:
        cmd.configure_sub(sub, p)
    add_global_options(p, cmd.overrides)
    if cmd.target != "none":
        add_load_options(p, cmd.overrides)
    return p


def parse(argv: list[str]) -> tuple[Command | None, argparse.Namespace, list[str], list[str]]:
    """Returns (command, merged namespace, passthrough tokens, the argv of the command)."""
    gp = _global_parser()
    idx = first_positional(argv, gp)
    head, tail = argv[:idx], argv[idx:]
    ns = gp.parse_args(head)
    if getattr(ns, "chdir", None):
        try:
            os.chdir(ns.chdir)
        except OSError as error:
            raise IdaxError(Exit.NOT_FOUND, f"-C {ns.chdir}: {error.strerror}", "NOTFOUND")
    if not tail:
        return None, ns, [], []
    name, rest = tail[0], tail[1:]
    load_commands()
    if name not in COMMANDS:
        from .config import CONFIG

        alias = (CONFIG.get("alias") or {}).get(name)
        if alias:
            expanded = shlex.split(alias)
            return parse(head + expanded + rest)
        raise usage(f"unknown command {name!r} (see: icli help)")
    cmd = COMMANDS[name]
    passthrough: list[str] = []
    if cmd.passthrough and "--" in rest:
        i = rest.index("--")
        rest, passthrough = rest[:i], rest[i + 1:]
    sub = None
    if cmd.subcommands:
        probe = command_parser(cmd)
        j = first_positional(rest, probe)
        if j < len(rest):
            sub = rest[j]
            if sub not in cmd.subcommands:
                raise usage(f"icli {name}: unknown subcommand {sub!r} "
                            f"(one of: {', '.join(cmd.subcommands)})")
            rest = rest[:j] + rest[j + 1:]
        elif not any(t in ("-h", "--help") for t in rest):
            raise usage(f"icli {name}: missing subcommand (one of: {', '.join(cmd.subcommands)})")
    rest = _optional_values(cmd, rest)
    cp = command_parser(cmd, sub)
    cns = cp.parse_intermixed_args(rest)
    merged = argparse.Namespace(**{**vars(ns), **vars(cns)})
    merged.sub = sub
    return cmd, merged, passthrough, tail


def _optional_values(cmd: Command, rest: list[str]) -> list[str]:
    """``--bytes [N]``: a following token is the value only when acceptable;
    otherwise the flag takes its default and the token stays positional."""
    if not cmd.optional_values:
        return rest
    out: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        spec = cmd.optional_values.get(tok)
        if spec is not None:
            default, accepts = spec
            if i + 1 < len(rest) and accepts(rest[i + 1]):
                out.append(f"{tok}={rest[i + 1]}")
                i += 2
                continue
            out.append(f"{tok}={default}")
            i += 1
            continue
        out.append(tok)
        i += 1
    return out


def general_help() -> str:
    load_commands()
    lines = ["usage: icli [global-options] command [command-options] [target] [selector...]", "",
             "Non-interactive IDA Pro: analysis, decompilation and annotation.", "", "commands:"]
    for group, _ in GROUPS:
        cmds = [c for c in COMMANDS.values() if c.group == group]
        lines.append(f"  {group}")
        for c in cmds:
            lines.append(f"    {c.name:<12} {c.summary}")
    lines += ["", "icli help COMMAND|TOPIC for details; topics: selectors, fields, templates, formats,",
              "exit-codes, journal, cache, recipes, settings, exec."]
    return "\n".join(lines) + "\n"


def version_text() -> str:
    from importlib.metadata import PackageNotFoundError, version

    from .env import idadir, kernel_version

    def v(pkg: str) -> str:
        try:
            return version(pkg)
        except PackageNotFoundError:
            return "?"

    lines = [f"icli {v('icli')}", f"kernel {kernel_version()} ({idadir() or 'IDA not found'})",
             f"ida-nexus {v('ida-nexus')}, ida-domain {v('ida-domain')}"]
    try:
        from .local import edition_info

        info = edition_info()
        lines.append(f"edition {info['edition']}")
        lines.append("decompilers " + (", ".join(info["decompilers"]) or "none"))
    except Exception as error:  # noqa: BLE001 - --version must not fail
        lines.append(f"edition unknown ({error})")
    return "\n".join(lines) + "\n"


def run(argv: list[str]) -> int:
    cmd, ns, passthrough, tail = parse(argv)
    if getattr(ns, "version", False):
        sys.stdout.write(version_text())
        return 0
    if cmd is None:
        sys.stdout.write(general_help())
        return 0 if getattr(ns, "help", False) else Exit.USAGE
    g = GlobalOptions.from_namespace(ns)
    if g.output.template and g.output.template.strip() == "":
        raise usage("empty template")
    emitter = Emitter(g.output, raw_field=cmd.raw_field)
    inv = Invocation(cmd, ns, g, emitter, argv=tail, passthrough=passthrough)
    # The database (analysis included) is saved unless the failure means its
    # state is suspect: internal errors, script errors, interrupts.
    save = True
    try:
        status = cmd.run(inv) or 0
        return combine(status, inv.status)
    except IdaxError as error:
        save = error.status not in (Exit.INTERNAL, Exit.SCRIPT, Exit.INTERRUPTED)
        raise
    except BaseException:
        save = False
        raise
    finally:
        try:
            inv.close(save)
        finally:
            emitter.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    fmt = _peek_format(args)
    try:
        return int(run(args))
    except IdaxError as error:
        _report(error.status, error.code, error.message, fmt)
        return error.status
    except KeyboardInterrupt:
        _report(Exit.INTERRUPTED, "INTERRUPTED", "interrupted", fmt)
        return Exit.INTERRUPTED
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")  # noqa: SIM115
        except OSError:
            pass
        return 0


def _peek_format(args: list[str]) -> str | None:
    for i, a in enumerate(args):
        if a in ("-f", "--format") and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--format="):
            return a.split("=", 1)[1]
    from .env import env

    return env("FORMAT")


def _report(status: int, code: str, message: str, fmt: str | None) -> None:
    emitter = Emitter(OutputOptions(format=fmt or None))
    level = "error"
    if fmt is None:
        emitter.format = "text"  # diagnostics read best as text when unasked
    emitter.diag(level, code, message)


def entry() -> None:
    sys.exit(main())
