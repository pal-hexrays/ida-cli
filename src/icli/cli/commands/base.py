"""Shared command shapes."""

from __future__ import annotations

import argparse
from typing import Any, ClassVar

from ..registry import Command, Invocation


class Remote(Command):
    """A command that is one engine operation over the target's selectors."""

    op: ClassVar[str]
    selectors_required: ClassVar[bool] = False

    def params(self, inv: Invocation, rest: list[str]) -> dict[str, Any]:
        return {"selectors": inv.selectors(rest) if rest else None}

    def run(self, inv: Invocation) -> int:
        rest = inv.positionals()
        if self.selectors_required and not rest:
            from ...errors import usage

            raise usage(f"icli {self.name}: at least one selector is required")
        params = self.params(inv, rest)
        if inv.g.show_code:
            from ..showcode import show_code

            inv.emitter.raw([show_code(self.op, params)])
            return 0
        inv.call(self.op, params)
        return 0


def add_edit_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--message", "-m", metavar="TEXT", default=None, help="journal annotation")
    p.add_argument("--force", action="store_true", help="overwrite values set by a user")
