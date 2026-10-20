"""Meta commands: help (config, schema, completion, legacy live in their own modules)."""

from __future__ import annotations

import argparse
import sys

from ...errors import usage
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
