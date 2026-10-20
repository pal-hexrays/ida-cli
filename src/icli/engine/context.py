"""Per-call engine context: the database, call options, warnings, records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import ida_idaapi

from ..errors import Exit, IdaxError, combine


class Addr(int):
    """An address.  Rendered per ``--addr`` style when results leave the engine."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"Addr({int(self):#x})"


def A(ea: int | None) -> Addr | None:
    """Wrap an address; ``None`` and BADADDR become ``None``."""
    if ea is None:
        return None
    ea = int(ea)
    if ea == ida_idaapi.BADADDR:
        return None
    return Addr(ea)


@dataclass
class Options:
    addr: str = "hex"
    fields: list[str] | None = None
    demangle: bool | None = None
    strict: bool = False
    dry_run: bool = False
    force: bool = False
    read_only: bool = False
    author: str = ""
    message: str = ""
    command: str = ""
    limit: int | None = None
    jobs: int = 1
    maturity: str = "lvars"

    @classmethod
    def from_dict(cls, data: dict) -> "Options":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Ctx:
    db: Any
    opts: Options
    prev: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    status: int = 0
    raw: list[str] = field(default_factory=list)
    changes: int = 0
    extra: dict = field(default_factory=dict)   # op-specific response fields (exec stdout/stderr)

    def warn(self, code: str, msg: str) -> None:
        """Record a warning; under --strict a warning is an error."""
        if self.opts.strict:
            raise IdaxError(Exit.NEGATIVE if code == "NOMATCH" else Exit.USAGE, msg, code)
        self.warnings.append({"_t": "diag", "level": "warning", "code": code, "msg": msg})

    def set_status(self, status: int) -> None:
        self.status = combine(self.status, int(status))

    def require_writable(self) -> None:
        if self.opts.read_only:
            raise IdaxError(Exit.READ_ONLY, "database is open read-only", "READONLY")
