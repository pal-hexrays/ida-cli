"""Selector grammar (SELECTORS in icli(1)).

A selector is parsed into a JSON-serialisable AST of plain dicts so that it
can be validated by the client (usage errors exit 2 before any database is
opened) and evaluated by the engine inside IDA.

Node shapes (``op`` key):

    union/inter/diff  {"op", "args": [node, ...]}
    not               {"op", "arg": node}
    pred              {"op", "arg": node, "expr": "text"}
    typed             {"op", "type": "func"|"seg"|..., "pattern": str, "regex": bool, "flags": str}
    func_at           {"op", "addr": addrexpr}
    class             {"op", "name": "lib"|"thunk"|...}
    graph             {"op", "name": "callers"|..., "arg": node, "depth": int|None, "closure": bool}
    addr              {"op", "expr": addrexpr}
    range             {"op", "start": addrexpr, "end": addrexpr|None, "size": addrexpr|None}
    prev              {"op"}                         -- %  (icli do)
    stdin             {"op"}                         -- -  (replaced by the client)
    file              {"op", "path": str}            -- @file (replaced by the client)
    items             {"op", "items": [record, ...]} -- records from stdin/file
    handle            {"op", "name": str}            -- @name database handles never reach here

``addrexpr`` is ``{"terms": [[sign, atom], ...]}`` with atoms
``{"num": int}``, ``{"name": str}``, ``{"sym": "entry"|"base"|"min"|"max"}``,
``{"rva": int}``, ``{"off": int}``, ``{"seg": str, "num": int}``.
"""

from __future__ import annotations

import re
from typing import Any

from ..errors import usage
from .expr import parse as parse_expr
from .values import is_bare_decimal, parse_address_number

TYPED = {"func", "seg", "name", "str", "imp", "exp", "type", "bytes", "tag", "diff"}
CLASSES = {"lib", "thunk", "noret", "dummy", "named", "patched", "lumina", "problem", "entry"}
GRAPH = {"callers", "callees", "xrefs", "drefs", "crefs", "refs", "blocks", "func", "uses_type"}
SYMBOLS = {"entry", "base", "min", "max"}

_SPECIAL = set("()|&,[]~")


class _Scanner:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def error(self, msg: str) -> Exception:
        return usage(f"malformed selector {self.text!r}: {msg} at offset {self.pos}")

    def skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def peek(self) -> str:
        self.skip_ws()
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def at_end(self) -> bool:
        return self.peek() == ""

    def expect(self, ch: str) -> None:
        if self.peek() != ch:
            raise self.error(f"expected {ch!r}")
        self.pos += 1

    def word(self) -> str:
        """A run of non-special characters; quoted strings are kept quoted."""
        self.skip_ws()
        start = self.pos
        t = self.text
        while self.pos < len(t):
            c = t[self.pos]
            if c in "\"'":
                end = self._quote_end(self.pos)
                self.pos = end
                continue
            if c == "/" and self.pos > start and t[self.pos - 1] == ":":
                # regex body after a typed prefix: func:/^ssl_/i
                end = t.find("/", self.pos + 1)
                while end > 0 and t[end - 1] == "\\":
                    end = t.find("/", end + 1)
                if end < 0:
                    raise self.error("unterminated regular expression")
                self.pos = end + 1
                while self.pos < len(t) and t[self.pos].isalpha():
                    self.pos += 1
                continue
            if c.isspace() or c in _SPECIAL:
                break
            self.pos += 1
        return t[start : self.pos]

    def _quote_end(self, start: int) -> int:
        q = self.text[start]
        i = start + 1
        while i < len(self.text):
            if self.text[i] == "\\":
                i += 2
                continue
            if self.text[i] == q:
                return i + 1
            i += 1
        raise self.error("unterminated quote")

    def bracket(self) -> str:
        """Raw text of a ``[...]`` predicate, honouring quotes and nesting."""
        self.expect("[")
        start = self.pos
        depth = 1
        while self.pos < len(self.text):
            c = self.text[self.pos]
            if c in "\"'":
                self.pos = self._quote_end(self.pos)
                continue
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    body = self.text[start : self.pos]
                    self.pos += 1
                    return body
            self.pos += 1
        raise self.error("unterminated '['")


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return re.sub(r"\\(.)", r"\1", s[1:-1])
    return s


def _pattern(text: str) -> tuple[str, bool, str]:
    """Split a glob or /re/flags pattern."""
    if len(text) >= 2 and text.startswith("/"):
        end = text.rfind("/")
        if end > 0:
            flags = text[end + 1 :]
            if flags and not re.fullmatch(r"[imsx]*", flags):
                raise usage(f"bad regular expression flags {flags!r} in {text!r}")
            body = text[1:end]
            try:
                re.compile(body)
            except re.error as error:
                raise usage(f"bad regular expression {body!r}: {error}")
            return body, True, flags
    return _unquote(text), False, ""


def _atom(text: str, offset: bool = False) -> dict:
    t = text.strip()
    if not t:
        raise usage("empty address atom")
    if t.startswith(("\"", "'")):
        return {"name": _unquote(t), "demangled": True}
    if t.startswith("$"):
        sym = t[1:]
        if sym not in SYMBOLS:
            raise usage(f"unknown address symbol {t!r} (expected $entry, $base, $min, $max)")
        return {"sym": sym}
    num = parse_address_number(t)
    if num is not None:
        return {"num": num}
    if is_bare_decimal(t):
        if offset:
            return {"num": int(t.replace("_", ""))}
        raise usage(f"bare decimal {t!r} is ambiguous; write 0x{t} or 0d{t}")
    head, sep, tail = t.partition(":")
    if sep and tail and ":" not in tail:
        if head in {"rva", "off"}:
            n = parse_address_number(tail)
            if n is None:
                if is_bare_decimal(tail):
                    raise usage(f"bare decimal {tail!r} is ambiguous; write 0x{tail}")
                raise usage(f"bad {head}: offset {tail!r}")
            return {head: n}
        n = parse_address_number(tail)
        if n is None and re.fullmatch(r"[0-9a-fA-F]+", tail):
            n = int(tail, 16)  # .text:00401000 (IDA listing style is always hex)
        if n is not None:
            return {"seg": head, "num": n}
    return {"name": t}


_ARITH = re.compile(r"(?<=[^+\-])([+\-])(?=(?:0[xXdDbBoO])?[0-9$])")


def parse_addrexpr(text: str) -> dict:
    """Parse ``main+0x2c``, ``$entry-4``, ``0x401000``, ``.text:401000``."""
    text = text.strip()
    if text.startswith(("\"", "'")):
        # quoted demangled name, possibly followed by arithmetic
        end = 1
        while end < len(text) and text[end] != text[0]:
            end += 2 if text[end] == "\\" else 1
        head, rest = text[: end + 1], text[end + 1 :]
    else:
        head, rest = text, ""
        m = _ARITH.search(text)
        if m:
            head, rest = text[: m.start()], text[m.start() :]
    terms: list[list[Any]] = [["+", _atom(head)]]
    while rest:
        m = re.match(r"\s*([+\-])\s*([^+\-]+)", rest)
        if not m:
            raise usage(f"malformed address expression {text!r}")
        terms.append([m.group(1), _atom(m.group(2), offset=True)])
        rest = rest[m.end() :]
    return {"terms": terms}


def _classify(word: str, sc: _Scanner) -> dict:
    if word == "%":
        return {"op": "prev"}
    if word == "-":
        return {"op": "stdin"}
    if word.startswith("@") and len(word) > 1:
        return {"op": "file", "path": word[1:]}
    if word in CLASSES:
        return {"op": "class", "name": word}
    if word.startswith("func@"):
        return {"op": "func_at", "addr": parse_addrexpr(word[5:])}
    prefix, sep, rest = word.partition(":")
    if sep and prefix in TYPED:
        if prefix == "imp":
            # imp:mod!sym, imp:*!recv, imp:recv (any module)
            mod, bang, sym = rest.rpartition("!")
            if not bang:
                mod, sym = "*", rest
            mpat, mre, mfl = _pattern(mod or "*")
            spat, sre, sfl = _pattern(sym or "*")
            return {"op": "typed", "type": "imp", "module": mpat, "module_regex": mre,
                    "pattern": spat, "regex": sre, "flags": sfl or mfl}
        if prefix == "bytes":
            hexs = rest.replace(" ", "")
            if not hexs or not re.fullmatch(r"([0-9a-fA-F?]{2})+", hexs):
                raise usage(f"bad byte pattern {rest!r} (hex digits, ?? for wildcards)")
            return {"op": "typed", "type": "bytes", "pattern": hexs, "regex": False, "flags": ""}
        pat, is_re, flags = _pattern(rest if rest else "*")
        return {"op": "typed", "type": prefix, "pattern": pat, "regex": is_re, "flags": flags}
    if ".." in word and not word.startswith(("\"", "'")):
        start, _, end = word.partition("..")
        return {"op": "range", "start": parse_addrexpr(start),
                "end": parse_addrexpr(end) if end else None, "size": None}
    m = re.fullmatch(r"(0[xX][0-9a-fA-F_]+|0[dD][0-9_]+|[0-9][0-9a-fA-F_]*[hH])\+(.+)", word)
    if m:
        return {"op": "range", "start": parse_addrexpr(m.group(1)), "end": None,
                "size": parse_addrexpr(m.group(2))}
    return {"op": "addr", "expr": parse_addrexpr(word)}


class _Parser:
    def __init__(self, text: str) -> None:
        self.sc = _Scanner(text)

    def parse(self) -> dict:
        if self.sc.at_end():
            raise usage("empty selector")
        node = self.union()
        if not self.sc.at_end():
            raise self.sc.error(f"unexpected {self.sc.peek()!r}")
        return node

    def union(self) -> dict:
        args = [self.diff()]
        while self.sc.peek() in {",", "|"}:
            self.sc.pos += 1
            args.append(self.diff())
        return args[0] if len(args) == 1 else {"op": "union", "args": args}

    def diff(self) -> dict:
        args = [self.inter()]
        while self.sc.peek() == "~":
            self.sc.pos += 1
            args.append(self.inter())
        return args[0] if len(args) == 1 else {"op": "diff", "args": args}

    def inter(self) -> dict:
        args = [self.unary()]
        while self.sc.peek() == "&":
            self.sc.pos += 1
            args.append(self.unary())
        return args[0] if len(args) == 1 else {"op": "inter", "args": args}

    def unary(self) -> dict:
        sc = self.sc
        if sc.peek() == "!":
            sc.pos += 1
            return {"op": "not", "arg": self.unary()}
        return self.postfix()

    def postfix(self) -> dict:
        node = self.primary()
        while self.sc.peek() == "[":
            body = self.sc.bracket()
            parse_expr(body)  # validate now
            node = {"op": "pred", "arg": node, "expr": body}
        return node

    def primary(self) -> dict:
        sc = self.sc
        c = sc.peek()
        if c == "(":
            sc.pos += 1
            node = self.union()
            sc.expect(")")
            return node
        if c == "" or c in _SPECIAL:
            raise sc.error("expected a selector")
        word = sc.word()
        if not word:
            raise sc.error("expected a selector")
        name, star = (word[:-1], True) if word.endswith("*") else (word, False)
        if name in GRAPH and sc.peek() == "(":
            return self.graph(name, star)
        return _classify(word, sc)

    def graph(self, name: str, closure: bool) -> dict:
        sc = self.sc
        sc.expect("(")
        if name == "uses_type":
            word = sc.word()
            sc.expect(")")
            pat, is_re, flags = _pattern(word)
            return {"op": "graph", "name": name, "pattern": pat, "regex": is_re,
                    "flags": flags, "arg": None, "depth": None, "closure": False}
        arg = self.diff_inner()
        depth = None
        if sc.peek() == ",":
            sc.pos += 1
            word = sc.word()
            try:
                depth = int(word, 0)
            except ValueError:
                raise sc.error(f"bad depth {word!r}")
            if depth < 1:
                raise sc.error("depth must be >= 1")
        sc.expect(")")
        return {"op": "graph", "name": name, "arg": arg, "depth": depth, "closure": closure}

    def diff_inner(self) -> dict:
        """Inside graph operator parentheses a comma separates the depth, so
        union there must be written with ``|``."""
        args = [self.diff()]
        while self.sc.peek() == "|":
            self.sc.pos += 1
            args.append(self.diff())
        return args[0] if len(args) == 1 else {"op": "union", "args": args}


def parse(text: str) -> dict:
    """Parse one selector argument into an AST."""
    return _Parser(text).parse()


def walk(node: dict):
    """Yield every node in an AST."""
    yield node
    for key in ("arg",):
        if isinstance(node.get(key), dict):
            yield from walk(node[key])
    for child in node.get("args", ()):
        yield from walk(child)


def uses(node: dict, op: str) -> bool:
    return any(n.get("op") == op for n in walk(node))


def replace(node: dict, fn) -> dict:
    """Return a copy of the AST with ``fn(node)`` applied bottom-up where it
    returns a replacement (or ``None`` to keep the node)."""
    new = dict(node)
    if isinstance(new.get("arg"), dict):
        new["arg"] = replace(new["arg"], fn)
    if "args" in new:
        new["args"] = [replace(a, fn) for a in new["args"]]
    out = fn(new)
    return new if out is None else out
