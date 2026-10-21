"""``icli ref``: the ida-domain API reference served by ida-mcp's
``reference`` tool, built by ida-nexus from the installed ida-domain (so it
never disagrees with the API it describes).  Works offline, no target."""

from __future__ import annotations

import importlib
from typing import Any

from ..errors import Exit, IcliError


def _spec() -> dict[str, Any]:
    try:
        ref = importlib.import_module("ida_nexus.reference")
        return ref._build_reference_spec()  # noqa: SLF001 - the index behind the public reference()
    except Exception as error:  # noqa: BLE001
        raise IcliError(Exit.INTERNAL, f"cannot build the ida-domain reference index: {error}", "INTERR")


def _example(spec: dict[str, Any], name: str) -> str:
    """A few lines of a shipped example that use ``name``."""
    short = name.rsplit(".", 1)[-1]
    for ex in spec["example_index"].search(short)[:5]:
        lines = ex["content"].splitlines()
        for i, line in enumerate(lines):
            if f".{short}(" in line or f" {short}(" in line:
                lo = max(0, i - 2)
                snippet = [ln for ln in lines[lo: i + 3] if ln.strip()]
                return "\n".join(snippet) + f"\n# from {ex['path']}"
    return ""


def search(query: str, n: int = 5, *, full: bool = False) -> list[dict]:
    spec = _spec()
    out = []
    for e in spec["entry_index"].search(query)[: max(n, 0)]:
        doc = str(e.get("doc", "")).strip()
        out.append({
            "_t": "ref",
            "symbol": e["qualname"],
            "kind": e["kind"],
            "signature": f"{e['qualname']}{e.get('signature', '')}",
            "doc": doc if full else doc.split("\n\n")[0],
            "example": _example(spec, e["qualname"]),
            "source": f"{e['file']}:{e['line']}",
            "version": spec["version"],
        })
    return out
