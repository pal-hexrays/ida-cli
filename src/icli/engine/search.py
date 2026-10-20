"""Searching the database: byte patterns, immediates, text, strings, crypto."""

from __future__ import annotations

from typing import Iterator

import ida_bytes
import ida_ida
import ida_idaapi

BADADDR = ida_idaapi.BADADDR


def compile_bytes(pattern: str) -> ida_bytes.compiled_binpat_vec_t:
    """Compile an IDA binary pattern ("55 8B EC ?? 83" or "558BEC??83")."""
    text = pattern.strip()
    if " " not in text and len(text) % 2 == 0:
        text = " ".join(text[i:i + 2] for i in range(0, len(text), 2))
    vec = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(vec, ida_ida.inf_get_min_ea(), text, 16)
    if err is False or err is None and vec.empty():
        from ..errors import Exit, IdaxError

        raise IdaxError(Exit.USAGE, f"bad byte pattern {pattern!r}", "USAGE")
    return vec


def find_bytes(pattern: str, start: int | None = None, end: int | None = None) -> Iterator[int]:
    vec = compile_bytes(pattern)
    ea = ida_ida.inf_get_min_ea() if start is None else start
    hi = ida_ida.inf_get_max_ea() if end is None else end
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
    while ea < hi:
        found = ida_bytes.bin_search(ea, hi, vec, flags)
        if isinstance(found, tuple):
            found = found[0]
        if found == BADADDR or found >= hi:
            return
        yield found
        ea = found + 1
