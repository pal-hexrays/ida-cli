"""Text templates: ``{field}`` and ``{field:spec}`` placeholders.

Used by ``-t``, ``--header``/``--footer``, edit arguments (``rename ...
'f_{hash:.8}'``) and ``-o`` output paths.  See FIELDS AND TEMPLATES in idx(1).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..errors import usage

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_ESCAPES = {"n": "\n", "t": "\t", "0": "\0", "\\": "\\", "r": "\r"}
_NUMERIC_SPEC = re.compile(r"[#0-9,_]*[bcdoxXneEfFgG%]$")
_INVALID_PATH_CHARS = re.compile(r'[\x00-\x1f<>:"|?*\\]')


@dataclass(frozen=True)
class _Field:
    name: str
    spec: str


@dataclass(frozen=True)
class Template:
    """A parsed template: literal strings interleaved with fields."""

    parts: tuple[str | _Field, ...]
    newline: bool

    @property
    def fields(self) -> list[str]:
        """Field names referenced, in order of first appearance."""
        seen: dict[str, None] = {}
        for p in self.parts:
            if isinstance(p, _Field):
                seen.setdefault(p.name, None)
        return list(seen)

    @property
    def is_static(self) -> bool:
        return not any(isinstance(p, _Field) for p in self.parts)

    def render(self, record: Mapping[str, Any] | Callable[[str], Any]) -> str:
        get = record if callable(record) else (lambda name: lookup(record, name))
        out: list[str] = []
        for p in self.parts:
            if isinstance(p, str):
                out.append(p)
            else:
                out.append(format_value(get(p.name), p.spec, p.name))
        text = "".join(out)
        return text + "\n" if self.newline else text


def lookup(record: Mapping[str, Any], name: str) -> Any:
    """Look up ``name`` in a record; dotted names descend into mappings."""
    if name in record:
        return record[name]
    value: Any = record
    for part in name.split("."):
        if isinstance(value, Mapping) and part in value:
            value = value[part]
        else:
            return None
    return value


def _coerce_number(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        try:
            if s.lower().startswith(("0x", "-0x")):
                return int(s, 16)
            if re.fullmatch(r"-?\d+", s):
                return int(s)
            return float(s)
        except ValueError:
            return value
    return value


def format_value(value: Any, spec: str = "", name: str = "") -> str:
    if value is None:
        value = ""
    if isinstance(value, (list, tuple)):
        if spec and not _NUMERIC_SPEC.search(spec) and not re.fullmatch(r"[<>^=]?\d*(\.\d+)?", spec):
            # {tags:,} — the spec is the separator
            return spec.join(_scalar(v) for v in value)
        value = ",".join(_scalar(v) for v in value)
    elif isinstance(value, dict):
        value = json.dumps(value, separators=(",", ":"))
    elif isinstance(value, bool):
        value = "true" if value else "false"
    if not spec:
        return str(value)
    try:
        return format(value, spec)
    except (ValueError, TypeError):
        coerced = _coerce_number(value)
        try:
            return format(coerced, spec)
        except (ValueError, TypeError):
            try:
                return format(str(value), spec)
            except (ValueError, TypeError) as error:
                raise usage(f"bad format spec {{{name}:{spec}}} for value {value!r}: {error}")


def _scalar(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"))
    if v is None:
        return ""
    return str(v)


def parse(text: str, *, record_newline: bool = True) -> Template:
    """Parse a template.

    Escapes ``\\n``, ``\\t``, ``\\0`` are recognised.  A rendered record gets a
    trailing newline unless the template ends with ``\\c`` (or
    ``record_newline`` is false, as for edit arguments and paths).
    """
    parts: list[str | _Field] = []
    buf: list[str] = []
    newline = record_newline
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "c" and i + 2 == n:
                newline = False
                i += 2
                continue
            if nxt in _ESCAPES:
                buf.append(_ESCAPES[nxt])
                i += 2
                continue
            buf.append(c)
            i += 1
            continue
        if c == "{":
            if text.startswith("{{", i):
                buf.append("{")
                i += 2
                continue
            end = text.find("}", i)
            if end < 0:
                raise usage(f"unterminated placeholder in template: {text!r}")
            body = text[i + 1 : end]
            name, _, spec = body.partition(":")
            name = name.strip()
            if not _NAME.fullmatch(name):
                raise usage(f"bad placeholder {{{body}}} in template: {text!r}")
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append(_Field(name, spec))
            i = end + 1
            continue
        if c == "}":
            if text.startswith("}}", i):
                buf.append("}")
                i += 2
                continue
            raise usage(f"single '}}' in template: {text!r}")
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return Template(tuple(parts), newline)


def has_placeholders(text: str) -> bool:
    try:
        return not parse(text, record_newline=False).is_static
    except Exception:
        return False


def render_inline(text: str, record: Mapping[str, Any] | Callable[[str], Any]) -> str:
    """Render an edit argument template (no trailing newline)."""
    return parse(text, record_newline=False).render(record)


def sanitize_path_component(text: str) -> str:
    """Replace characters invalid in file names with ``_``."""
    return _INVALID_PATH_CHARS.sub("_", text).replace("/", "_") or "_"


def render_path(text: str, record: Mapping[str, Any]) -> str:
    """Render an ``-o`` path template; field values are sanitised, literal
    path separators in the template are kept."""
    tpl = parse(text, record_newline=False)
    out: list[str] = []
    for p in tpl.parts:
        if isinstance(p, str):
            out.append(p)
        else:
            raw = lookup(record, p.name)
            out.append(sanitize_path_component(format_value(raw, p.spec, p.name)) if raw is not None else "")
    return "".join(out)
