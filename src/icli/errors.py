"""Exit statuses and the error type shared by the client and the engine.

The codes are the stable interface documented under EXIT STATUS in idx(1).
"""

from __future__ import annotations

from enum import IntEnum


class Exit(IntEnum):
    OK = 0
    NEGATIVE = 1
    USAGE = 2
    PARTIAL = 3
    NOT_FOUND = 4
    EMPTY_SELECTION = 5
    LOAD = 6
    LICENSE = 7
    DECOMPILE = 8
    CONFLICT = 9
    TIMEOUT = 10
    LOCKED = 11
    STATE = 12
    READ_ONLY = 13
    CORRUPT = 14
    NETWORK = 15
    SCRIPT = 16
    INTERNAL = 70
    INTERRUPTED = 130


def combine(a: int, b: int) -> int:
    """Combine two exit statuses.

    The lowest non-zero code wins, except that 3 (partial) yields to any
    hard error.
    """
    codes = [c for c in (a, b) if c]
    if not codes:
        return 0
    hard = [c for c in codes if c != Exit.PARTIAL]
    if hard and Exit.PARTIAL in codes:
        return min(hard)
    return min(codes)


class IdaxError(Exception):
    """An error carrying the exit status it maps to.

    ``code`` is a short machine-readable diagnostic identifier, used in
    JSON diagnostics (``{"_t":"diag","code":...}``).
    """

    def __init__(self, status: int, message: str, code: str = "ERROR") -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = message
        self.code = code

    def to_dict(self) -> dict:
        return {"status": self.status, "message": self.message, "code": self.code}

    @classmethod
    def from_dict(cls, data: dict) -> "IdaxError":
        return cls(int(data["status"]), str(data["message"]), str(data.get("code", "ERROR")))


def usage(message: str) -> IdaxError:
    return IdaxError(Exit.USAGE, message, "USAGE")
