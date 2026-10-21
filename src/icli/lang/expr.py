"""Predicate expressions over record fields.

    size > 0x400 && !lib
    module ~ "(?i)ws2_32"
    insns > 200 && hexrays_err != 0

Operators: ``== != < <= > >= && || !`` and ``~`` (regex search on strings),
plus ``+ - * /`` arithmetic and parentheses.  A bare field in a boolean
context tests its truthiness.  Used by ``list --where`` and selector
predicates; see SELECTORS / Predicates in icli(1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from ..errors import usage

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*\.\d+|\d[\d_]*)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<op>&&|\|\||==|!=|<=|>=|[<>!~()+\-*/])
  | (?P<ident>[A-Za-z_$][A-Za-z0-9_.$]*)
    """,
    re.X,
)


@dataclass(frozen=True)
class Node:
    kind: str  # "lit", "field", "not", "neg", "bin"
    value: Any = None
    left: "Node | None" = None
    right: "Node | None" = None


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise usage(f"malformed predicate at {text[pos:]!r} in {text!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        if kind == "ws":
            continue
        out.append((kind, m.group(kind)))
    return out


def _unquote(s: str) -> str:
    body = s[1:-1]
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), body)


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.toks = _tokens(text)
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok is None or (value is not None and tok[1] != value):
            want = f"{value!r}" if value else "a term"
            got = repr(tok[1]) if tok else "end of input"
            raise usage(f"malformed predicate {self.text!r}: expected {want}, got {got}")
        self.i += 1
        return tok

    def parse(self) -> Node:
        if not self.toks:
            raise usage("empty predicate")
        node = self.or_()
        extra = self.peek()
        if extra is not None:
            raise usage(f"malformed predicate {self.text!r}: unexpected {extra[1]!r}")
        return node

    def or_(self) -> Node:
        node = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            node = Node("bin", "||", node, self.and_())
        return node

    def and_(self) -> Node:
        node = self.not_()
        while self.peek() == ("op", "&&"):
            self.take()
            node = Node("bin", "&&", node, self.not_())
        return node

    def not_(self) -> Node:
        if self.peek() == ("op", "!"):
            self.take()
            return Node("not", left=self.not_())
        return self.cmp()

    def cmp(self) -> Node:
        node = self.sum()
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in {"==", "!=", "<", "<=", ">", ">=", "~"}:
            self.take()
            node = Node("bin", tok[1], node, self.sum())
        return node

    def sum(self) -> Node:
        node = self.prod()
        while self.peek() in (("op", "+"), ("op", "-")):
            op = self.take()[1]
            node = Node("bin", op, node, self.prod())
        return node

    def prod(self) -> Node:
        node = self.unary()
        while self.peek() in (("op", "*"), ("op", "/")):
            op = self.take()[1]
            node = Node("bin", op, node, self.unary())
        return node

    def unary(self) -> Node:
        if self.peek() == ("op", "-"):
            self.take()
            return Node("neg", left=self.unary())
        if self.peek() == ("op", "!"):
            self.take()
            return Node("not", left=self.unary())
        return self.primary()

    def primary(self) -> Node:
        kind, value = self.take()
        if kind == "num":
            v = value.replace("_", "")
            if v[:2].lower() == "0x":
                return Node("lit", int(v, 16))
            if v[:2].lower() == "0b":
                return Node("lit", int(v, 2))
            return Node("lit", float(v) if "." in v else int(v))
        if kind == "str":
            return Node("lit", _unquote(value))
        if kind == "ident":
            low = value.lower()
            if low == "true":
                return Node("lit", True)
            if low == "false":
                return Node("lit", False)
            if low in {"null", "none"}:
                return Node("lit", None)
            return Node("field", value)
        if value == "(":
            node = self.or_()
            self.take(")")
            return node
        raise usage(f"malformed predicate {self.text!r}: unexpected {value!r}")


_CACHE: dict[str, Node] = {}


def parse(text: str) -> Node:
    node = _CACHE.get(text)
    if node is None:
        node = _CACHE[text] = _Parser(text).parse()
    return node


def fields(node: Node) -> list[str]:
    """Field names referenced by an expression."""
    out: dict[str, None] = {}

    def walk(n: Node | None) -> None:
        if n is None:
            return
        if n.kind == "field":
            out.setdefault(n.value, None)
        walk(n.left)
        walk(n.right)

    walk(node)
    return list(out)


def _num(v: Any) -> Any:
    """Coerce address strings ("0x401000") and numeric strings for comparison."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
            if re.fullmatch(r"-?\d+", s):
                return int(s)
        except ValueError:
            pass
    return v


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v not in {"", "0", "false", "none"}
    return bool(v)


def _compare(op: str, a: Any, b: Any) -> bool:
    if op == "~":
        if a is None:
            return False
        if isinstance(a, (list, tuple)):
            return any(_compare("~", x, b) for x in a)
        try:
            return re.search(str(b), str(a)) is not None
        except re.error as error:
            raise usage(f"bad regular expression {b!r}: {error}")
    na, nb = _num(a), _num(b)
    if (a is None) != (b is None):
        return False  # a missing value compares false (unless compared with null itself)
    if op == "==":
        if isinstance(na, (list, tuple)) and not isinstance(nb, (list, tuple)):
            return nb in na
        return na == nb
    if op == "!=":
        return not _compare("==", a, b)
    if na is None or nb is None:
        return False
    try:
        if op == "<":
            return na < nb
        if op == "<=":
            return na <= nb
        if op == ">":
            return na > nb
        if op == ">=":
            return na >= nb
    except TypeError:
        return False
    raise usage(f"unknown operator {op}")


def evaluate(node: Node | None, get: Callable[[str], Any]) -> Any:
    if node is None:
        return None
    k = node.kind
    if k == "lit":
        return node.value
    if k == "field":
        return get(node.value)
    if k == "not":
        return not _truthy(evaluate(node.left, get))
    if k == "neg":
        v = _num(evaluate(node.left, get))
        return -v if isinstance(v, (int, float)) else None
    op = node.value
    if op == "&&":
        return _truthy(evaluate(node.left, get)) and _truthy(evaluate(node.right, get))
    if op == "||":
        return _truthy(evaluate(node.left, get)) or _truthy(evaluate(node.right, get))
    a = evaluate(node.left, get)
    b = evaluate(node.right, get)
    if op in {"+", "-", "*", "/"}:
        na, nb = _num(a), _num(b)
        if not isinstance(na, (int, float)) or not isinstance(nb, (int, float)):
            if op == "+" and isinstance(a, str) and isinstance(b, str):
                return a + b
            return None
        if op == "+":
            return na + nb
        if op == "-":
            return na - nb
        if op == "*":
            return na * nb
        return na / nb if nb else None
    return _compare(op, a, b)


def test(text_or_node: str | Node, get: Callable[[str], Any]) -> bool:
    node = parse(text_or_node) if isinstance(text_or_node, str) else text_or_node
    return _truthy(evaluate(node, get))
