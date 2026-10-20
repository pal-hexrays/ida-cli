"""JSON persistence inside the database, in named netnodes.

Everything icli stores travels with the .i64 (and through IDA Teams):
``$icli.journal`` (edit journal), ``$icli.tags``, ``$icli.coverage``,
``$icli.state`` (lifecycle).
"""

from __future__ import annotations

import json
from typing import Any, Iterator

import ida_netnode

_TAG_DOC = "J"
_TAG_LOG = "L"


def _node(name: str, create: bool = True) -> ida_netnode.netnode | None:
    n = ida_netnode.netnode(name, 0, create)
    if not create and n == ida_netnode.BADNODE:
        return None
    return n


class Doc:
    """One JSON document stored as a single blob."""

    def __init__(self, name: str) -> None:
        self.name = name

    def load(self, default: Any = None) -> Any:
        n = _node(self.name, create=False)
        if n is None:
            return default
        blob = n.getblob(0, _TAG_DOC)
        if not blob:
            return default
        return json.loads(blob.decode("utf-8"))

    def save(self, value: Any) -> None:
        n = _node(self.name)
        assert n is not None
        data = json.dumps(value, separators=(",", ":")).encode("utf-8")
        n.delblob(0, _TAG_DOC)
        n.setblob(data, 0, _TAG_DOC)


class Log:
    """Append-only list of JSON records; index 1..N, count in altval 0."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __len__(self) -> int:
        n = _node(self.name, create=False)
        return int(n.altval(0)) if n is not None else 0

    def append(self, record: dict) -> int:
        n = _node(self.name)
        assert n is not None
        idx = int(n.altval(0)) + 1
        n.setblob(json.dumps(record, separators=(",", ":")).encode("utf-8"), idx, _TAG_LOG)
        n.altset(0, idx)
        return idx

    def get(self, idx: int) -> dict | None:
        n = _node(self.name, create=False)
        if n is None:
            return None
        blob = n.getblob(idx, _TAG_LOG)
        return json.loads(blob.decode("utf-8")) if blob else None

    def __iter__(self) -> Iterator[dict]:
        for i in range(1, len(self) + 1):
            rec = self.get(i)
            if rec is not None:
                yield rec
