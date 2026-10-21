"""Meta commands: help, config, schema, completion, legacy."""

from __future__ import annotations

import argparse
import sys

from ...errors import Exit, IcliError, usage
from ..registry import COMMANDS, Command, Invocation, register


@register
class Help(Command):
    name = "help"
    group = "meta"
    summary = "help on a command or topic"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="command|topic")

    def run(self, inv: Invocation) -> int:
        from .. import manual
        from ..main import command_parser, general_help

        items = inv.args.items
        if not items:
            sys.stdout.write(general_help())
            return 0
        what = items[0]
        if what in COMMANDS:
            cmd = COMMANDS[what]
            sub = items[1] if len(items) > 1 and items[1] in cmd.subcommands else None
            sys.stdout.write(command_parser(cmd, sub).format_help())
            return 0
        if what in manual.TOPICS:
            sec, subsec = manual.TOPICS[what]
            text = manual.section(sec, subsec)
            if what in ("recipes", "exec"):
                text = manual.command_entry("do" if what == "recipes" else "exec") or text
            sys.stdout.write(text)
            return 0
        if what in ("manual", "man"):
            sys.stdout.write(manual.rendered())
            return 0
        raise usage(f"no help for {what!r}; topics: {', '.join(manual.TOPICS)}")


@register
class Config(Command):
    name = "config"
    group = "meta"
    summary = "read and write icli configuration (ida.cfg is never written; use --set)"
    target = "none"
    subcommands = {"get": "print a value", "set": "set a value", "unset": "remove a value",
                   "list": "list effective values"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="key [value]")
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("--global", dest="scope", action="store_const", const="global")
        scope.add_argument("--project", dest="scope", action="store_const", const="project")

    def run(self, inv: Invocation) -> int:
        from .. import config as cfg

        a = inv.args
        sub = a.sub
        items = a.items
        if sub == "list":
            data = cfg.read(self._path(a.scope)) if a.scope else self._effective()
            out = [{"_t": "config", "key": f"{sec}.{k}", "value": v}
                   for sec, table in data.items() if isinstance(table, dict) for k, v in table.items()]
            inv.emit(out)
            return 0
        if not items:
            raise usage(f"icli config {sub}: expected a key (section.name)")
        section, key = cfg.split_key(items[0])
        if sub == "get":
            data = cfg.read(self._path(a.scope)) if a.scope else self._effective()
            value = (data.get(section) or {}).get(key)
            if value is None:
                return Exit.NEGATIVE
            if inv.emitter.format == "text":
                sys.stdout.write(f"{value}\n")
            else:
                inv.emit([{"_t": "config", "key": items[0], "value": value}])
            return 0
        path = self._path(a.scope or "project")
        data = cfg.read(path) if path.exists() else {}
        if sub == "set":
            if len(items) != 2:
                raise usage("icli config set: expected KEY VALUE")
            if section in ("ida", "hexrays"):
                from .. import settings

                settings.parse([f"{'hexrays.' if section == 'hexrays' else ''}{key}={items[1]}"])
            data.setdefault(section, {})[key] = cfg.parse_value(items[1])
        elif sub == "unset":
            if key not in (data.get(section) or {}):
                return Exit.NEGATIVE
            del data[section][key]
            if not data[section]:
                del data[section]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cfg.dump(data))
        cfg.CONFIG.reload()
        inv.emit([{"_t": "config", "key": items[0], "value": (data.get(section) or {}).get(key),
                   "file": str(path)}])
        return 0

    @staticmethod
    def _path(scope: str | None):
        from .. import config as cfg

        if scope == "global":
            return cfg.global_path()
        return cfg.project_path() or cfg.project_path(create=True)

    @staticmethod
    def _effective() -> dict:
        from .. import config as cfg

        cfg.CONFIG.get("defaults")
        return dict(cfg.CONFIG)


@register
class Schema(Command):
    name = "schema"
    group = "meta"
    summary = "JSON Schema of the records a command emits"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="[command [kind]]")

    def run(self, inv: Invocation) -> int:
        from .. import schema

        items = inv.args.items
        version = inv.g.schema_version or 1
        if not items:
            names = sorted(set(schema.kinds()) | set(schema.RECORDS))
            inv.emit([{"_t": "schema", "id": f"icli.{n}/{version}", "record": n} for n in names])
            return 0
        command = items[0]
        if command not in COMMANDS and command not in schema.kinds() and command not in schema.RECORDS:
            raise usage(f"icli schema: unknown command or record {command!r}")
        records = [command] if command not in COMMANDS else schema.records_for_command(
            command, items[1] if len(items) > 1 else None)
        if not records:
            raise usage(f"icli schema: {command} emits no documented records")
        docs = [schema.schema_for(r, version) for r in records]
        if inv.emitter.format in ("text", "json"):
            import json

            sys.stdout.write(json.dumps(docs[0] if len(docs) == 1 else docs, indent=2) + "\n")
            return 0
        inv.emit([{"_t": "schema", **d} for d in docs])
        return 0


SHELLS = ("bash", "zsh", "fish", "powershell")


@register
class Completion(Command):
    name = "completion"
    group = "meta"
    summary = "shell completion script (names complete against the target's database)"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("shell", choices=SHELLS)

    def run(self, inv: Invocation) -> int:
        from ..completion import script

        sys.stdout.write(script(inv.args.shell))
        return 0


@register
class Complete(Command):
    """Hidden helper the completion scripts call: ``icli __complete WORD...``."""

    name = "__complete"
    group = "hidden"
    summary = ""
    target = "none"
    passthrough = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def run(self, inv: Invocation) -> int:
        from ..completion import candidates

        for c in candidates(list(inv.args.items) + list(inv.passthrough)):
            sys.stdout.write(c + "\n")
        return 0


@register
class Legacy(Command):
    name = "legacy"
    group = "meta"
    summary = "run an idat command line unchanged"
    target = "none"
    passthrough = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="-- idat-args")

    def run(self, inv: Invocation) -> int:
        import subprocess

        from ..env import idadir

        args = list(inv.passthrough) + list(inv.args.items)
        if not args:
            raise usage("icli legacy: expected -- IDAT-ARGUMENTS")
        d = idadir()
        idat = next((d / n for n in ("idat", "idat64", "idat.exe", "idat64.exe") if d and (d / n).exists()), None)
        if idat is None:
            raise IcliError(Exit.LICENSE, "idat not found in the IDA installation", "NOTOOL")
        return subprocess.call([str(idat), *args])
