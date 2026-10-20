"""Free-form item tags (``icli tag``), stored in ``$icli.tags``."""

from __future__ import annotations

import ida_nalt

from .store import Doc

_DOC = Doc("$icli.tags")
_cache: dict[int, list[str]] | None = None


def all_tags() -> dict[int, list[str]]:
    global _cache
    if _cache is None:
        raw = _DOC.load({}) or {}
        base = ida_nalt.get_imagebase()  # keys are image-base offsets: tags survive rebasing
        _cache = {base + int(k, 16): list(v) for k, v in raw.items()}
    return _cache


def get(ea: int) -> list[str]:
    return list(all_tags().get(ea, []))


def set_tags(ea: int, tags: list[str]) -> None:
    data = all_tags()
    if tags:
        data[ea] = sorted(dict.fromkeys(tags))
    else:
        data.pop(ea, None)
    base = ida_nalt.get_imagebase()
    _DOC.save({f"{k - base:#x}": v for k, v in sorted(data.items())})


def reset_cache() -> None:
    global _cache
    _cache = None
