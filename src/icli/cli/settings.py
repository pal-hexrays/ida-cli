"""``--set KEY=VALUE``: kernel and plugin configuration overrides.

Unqualified keys target ``ida.cfg``; ``prefix.KEY`` targets ``cfg/prefix.cfg``
(``hexrays.MAX_FUNCSIZE=128``).  Keys are validated against the installed
configuration files, because a mistyped override is the commonest cause of
"it did nothing" (status 2).  Flag words accept named bits:
``ANALYSIS=+FLIRT,-UNK``, ``hexrays.HEXOPTIONS=-COLLAPSE_LVARS``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..errors import usage
from .env import idadir, idausr

_DIRECTIVE = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*(?://.*)?$")
_DEFINE = re.compile(r"^\s*#define\s+([A-Z][A-Z0-9_]*)\s+(0[xX][0-9a-fA-F]+|\d+)")
_FLAGWORD = re.compile(r"^[+-][A-Za-z0-9_]+(,[+-][A-Za-z0-9_]+)*$")


@dataclass
class CfgFile:
    keys: dict[str, str] = field(default_factory=dict)      # key -> default value text
    defines: dict[str, int] = field(default_factory=dict)


def _cfg_paths(name: str) -> list[Path]:
    out = []
    d = idadir()
    if d:
        out.append(d / "cfg" / f"{name}.cfg")
    out.append(idausr() / "cfg" / f"{name}.cfg")
    if name == "ida":
        out.append(idausr() / "idauser.cfg")
    return out


@lru_cache(maxsize=None)
def cfg(name: str) -> CfgFile | None:
    found = CfgFile()
    seen = False
    for p in _cfg_paths(name):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        seen = True
        for line in text.splitlines():
            m = _DEFINE.match(line)
            if m:
                found.defines[m.group(1)] = int(m.group(2), 0)
                continue
            m = _DIRECTIVE.match(line)
            if m:
                found.keys.setdefault(m.group(1), m.group(2))
    return found if seen else None


def _bit(cf: CfgFile, name: str, key: str) -> int:
    name = name.upper()
    candidates = [v for k, v in cf.defines.items() if k == name or k.endswith("_" + name)]
    if len(candidates) != 1:
        raise usage(f"--set {key}: unknown flag {name!r}")
    return candidates[0]


def _default_value(cf: CfgFile, key: str) -> int:
    text = cf.keys.get(key, "0")
    text = text.strip().rstrip(";")
    try:
        return int(text, 0)
    except ValueError:
        total = 0
        for part in re.split(r"\s*\|\s*", text):
            if part in cf.defines:
                total |= cf.defines[part]
            else:
                try:
                    total |= int(part, 0)
                except ValueError:
                    pass
        return total


@dataclass
class Settings:
    ida: list[str] = field(default_factory=list)        # -D KEY=VALUE for the kernel
    hexrays: list[str] = field(default_factory=list)    # change_hexrays_config directives
    other: dict[str, list[str]] = field(default_factory=dict)


def parse(items: list[str], config_tables: dict | None = None) -> Settings:
    """Validate and translate ``--set`` items (plus [ida]/[hexrays] tables)."""
    out = Settings()
    pairs: list[tuple[str, str]] = []
    for table, prefix in (("ida", ""), ("hexrays", "hexrays.")):
        for k, v in ((config_tables or {}).get(table) or {}).items():
            pairs.append((prefix + k, v if isinstance(v, str) else str(v).upper() if isinstance(v, bool) else
                          str(v)))
    for item in items:
        key, eq, value = item.partition("=")
        if not eq or not key.strip():
            raise usage(f"--set expects KEY=VALUE, not {item!r}")
        pairs.append((key.strip(), value.strip()))
    for key, value in pairs:
        prefix, dot, name = key.rpartition(".")
        file = prefix if dot else "ida"
        if not dot:
            name = key
        cf = cfg(file)
        if cf is None:
            raise usage(f"--set {key}: no configuration file {file}.cfg")
        if name not in cf.keys:
            close = [k for k in cf.keys if k.startswith(name[:4])][:5]
            hint = f" (did you mean {', '.join(close)}?)" if close else ""
            raise usage(f"--set {key}: unknown key {name!r} in {file}.cfg{hint}")
        if _FLAGWORD.match(value):
            v = _default_value(cf, name)
            for part in value.split(","):
                bit = _bit(cf, part[1:], key)
                v = v | bit if part[0] == "+" else v & ~bit
            value = hex(v)
        directive = f"{name}={value}"
        if file == "ida":
            out.ida.append(directive)
        elif file == "hexrays":
            out.hexrays.append(f"{name} = {value}")
        else:
            out.other.setdefault(file, []).append(directive)
    return out
