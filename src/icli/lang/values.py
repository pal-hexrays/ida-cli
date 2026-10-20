"""Literal parsing shared by options, selectors and predicates."""

from __future__ import annotations

import re

from ..errors import usage

_HEX_PREFIX = re.compile(r"^0[xX][0-9a-fA-F_]+$")
_HEX_SUFFIX = re.compile(r"^[0-9][0-9a-fA-F_]*[hH]$")
_DEC_PREFIX = re.compile(r"^0[dD][0-9_]+$")
_BIN_PREFIX = re.compile(r"^0[bB][01_]+$")
_OCT_PREFIX = re.compile(r"^0[oO][0-7_]+$")
_DECIMAL = re.compile(r"^[0-9][0-9_]*$")


def parse_address_number(text: str) -> int | None:
    """Parse an address literal as accepted in selectors.

    Accepts ``0x401000``, ``401000h``, ``0x8000_1234`` and ``0d4198400``.
    A bare decimal is ambiguous (``401000`` could be hex) and is rejected:
    returns ``None`` for anything that is not an address literal.
    """
    t = text.strip()
    if _HEX_PREFIX.match(t):
        return int(t[2:].replace("_", ""), 16)
    if _DEC_PREFIX.match(t):
        return int(t[2:].replace("_", ""), 10)
    if _BIN_PREFIX.match(t):
        return int(t[2:].replace("_", ""), 2)
    if _OCT_PREFIX.match(t):
        return int(t[2:].replace("_", ""), 8)
    if _HEX_SUFFIX.match(t):
        return int(t[:-1].replace("_", ""), 16)
    return None


def is_bare_decimal(text: str) -> bool:
    return bool(_DECIMAL.match(text.strip()))


def parse_int(text: str | int) -> int:
    """Parse an integer option value: address literals plus plain decimals."""
    if isinstance(text, int):
        return text
    t = str(text).strip()
    neg = t.startswith("-")
    if neg:
        t = t[1:]
    value = parse_address_number(t)
    if value is None:
        if _DECIMAL.match(t):
            value = int(t.replace("_", ""))
        else:
            raise usage(f"not a number: {text!r}")
    return -value if neg else value


_DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?", re.I)
_DURATION_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, None: 1}


def parse_duration(text: str | float | int) -> float:
    """Parse ``90s``, ``15m``, ``2h``, ``1h30m``, ``7d`` into seconds."""
    if isinstance(text, (int, float)):
        return float(text)
    t = str(text).strip().lower()
    if not t:
        raise usage("empty duration")
    pos = 0
    total = 0.0
    while pos < len(t):
        m = _DURATION.match(t, pos)
        if not m or m.end() == pos:
            raise usage(f"malformed duration: {text!r} (expected e.g. 90s, 15m, 2h)")
        total += float(m.group(1)) * _DURATION_UNITS[m.group(2)]
        pos = m.end()
    return total


_SIZE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kmgt]?)(i?b)?$", re.I)
_SIZE_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}


def parse_size(text: str | int) -> int:
    """Parse ``50G``, ``512M``, ``1024`` into bytes."""
    if isinstance(text, int):
        return text
    m = _SIZE.match(str(text).strip())
    if not m:
        raise usage(f"malformed size: {text!r} (expected e.g. 512M, 50G)")
    return int(float(m.group(1)) * _SIZE_UNITS[m.group(2).lower()])


def parse_bool(text: str | bool) -> bool:
    if isinstance(text, bool):
        return text
    t = str(text).strip().lower()
    if t in {"1", "yes", "true", "on", "y"}:
        return True
    if t in {"0", "no", "false", "off", "n", ""}:
        return False
    raise usage(f"not a boolean: {text!r}")
