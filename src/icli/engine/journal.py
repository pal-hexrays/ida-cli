"""The edit journal (``$icli.journal``), stored inside the database.

Records: rev, time, author, command, kind, ea, key, before, after, message.
"""

from __future__ import annotations

import time
from typing import Iterator

from .store import Log

_LOG = Log("$icli.journal")


def length() -> int:
    return len(_LOG)


def revision() -> int:
    return len(_LOG)


def append(record: dict) -> dict:
    rec = dict(record)
    rec["rev"] = len(_LOG) + 1
    rec.setdefault("time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _LOG.append(rec)
    return rec


def records() -> Iterator[dict]:
    return iter(_LOG)


def get(rev: int) -> dict | None:
    return _LOG.get(rev)
