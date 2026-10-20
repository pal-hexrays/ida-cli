"""Execution coverage (``load coverage``, ``trace --coverage``), stored in
``$icli.coverage`` as hit counts per basic-block start."""

from __future__ import annotations

import bisect

import ida_nalt

from .store import Doc

_DOC = Doc("$icli.coverage")
_keys: list[int] | None = None
_hits: dict[int, int] = {}


def _load() -> None:
    global _keys, _hits
    if _keys is None:
        raw = _DOC.load({}) or {}
        base = ida_nalt.get_imagebase()  # keys are image-base offsets: hits survive rebasing
        _hits = {base + int(k, 16): int(v) for k, v in raw.items()}
        _keys = sorted(_hits)


def hits(start: int, end: int | None = None) -> int:
    """Total hits recorded in [start, end) (or at ``start``)."""
    _load()
    assert _keys is not None
    if end is None or end <= start:
        return _hits.get(start, 0)
    lo = bisect.bisect_left(_keys, start)
    hi = bisect.bisect_left(_keys, end)
    return sum(_hits[k] for k in _keys[lo:hi])


def add(counts: dict[int, int], replace: bool = False) -> int:
    """Merge hit counts; returns the number of distinct addresses stored."""
    global _keys
    _load()
    if replace:
        _hits.clear()
    for ea, n in counts.items():
        _hits[ea] = _hits.get(ea, 0) + int(n)
    base = ida_nalt.get_imagebase()
    _DOC.save({f"{k - base:#x}": v for k, v in sorted(_hits.items())})
    _keys = sorted(_hits)
    return len(_hits)


def all_hits() -> dict[int, int]:
    _load()
    return dict(_hits)
