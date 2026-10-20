"""Items, kinds and their named fields.

Every object icli knows about is an :class:`Item` of some :class:`Kind`.  A
kind names its fields once, as ``f_<field>`` methods; the same fields serve
as record keys, predicate variables, template placeholders and ``--fields``
(FIELDS AND TEMPLATES in idx(1)).  Values are computed lazily and cached per
item, so predicates only pay for what they reference.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Callable, Iterable, Iterator

import ida_bytes
import ida_funcs
import ida_ida
import ida_lines
import ida_nalt
import ida_name
import ida_segment

from ..context import A, Ctx

Getter = Callable[["Kind", "Item", Ctx], Any]

KINDS: dict[str, "Kind"] = {}
"""Kinds by singular and plural name (``function`` and ``functions``)."""


class Item:
    __slots__ = ("kind", "ea", "end", "obj", "key", "cache", "record")

    def __init__(self, kind: "Kind", ea: int | None, obj: Any = None, *, end: int | None = None,
                 key: Any = None, record: dict | None = None) -> None:
        self.kind = kind
        self.ea = ea
        self.end = end
        self.obj = obj
        self.key = key if key is not None else ea
        self.cache: dict[str, Any] = {}
        self.record = record

    def get(self, name: str, ctx: Ctx) -> Any:
        return self.kind.get(self, name, ctx)

    def __repr__(self) -> str:
        ea = f"{self.ea:#x}" if isinstance(self.ea, int) else self.ea
        return f"Item({self.kind.name}, {ea})"


class Kind:
    name = "address"
    plural = "addresses"
    record = "address"
    defaults: list[str] = ["ea", "name"]
    fields: dict[str, Getter] = {}

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)
        merged: dict[str, Getter] = {}
        for klass in reversed(cls.__mro__):
            for attr, value in vars(klass).items():
                if attr.startswith("f_") and callable(value):
                    merged[attr[2:]] = value
        cls.fields = merged

    # -- enumeration -----------------------------------------------------------

    def all(self, ctx: Ctx) -> Iterable[Item]:
        """Every item of this kind."""
        return ()

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        """The item of this kind at (or containing) ``ea``."""
        return Item(self, ea)

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        """Strings a glob/regex pattern is matched against."""
        n = self.get(it, "name", ctx)
        out = [n] if n else []
        d = self.get(it, "demangled", ctx) if "demangled" in self.fields else None
        if d and d != n:
            out.append(d)
        return out

    # -- fields ----------------------------------------------------------------

    def get(self, it: Item, name: str, ctx: Ctx) -> Any:
        if it.record is not None and name in it.record:
            return it.record[name]
        if name in it.cache:
            return it.cache[name]
        getter = self.fields.get(name)
        value = getter(self, it, ctx) if getter else None
        it.cache[name] = value
        return value

    def to_record(self, it: Item, ctx: Ctx, fields: list[str] | None = None) -> dict:
        rec: dict[str, Any] = {"_t": self.record}
        for f in fields or self.defaults:
            rec[f] = self.get(it, f, ctx)
        return rec

    # -- common fields (any item with an address) ---------------------------------

    def f_ea(self, it: Item, ctx: Ctx) -> Any:
        return A(it.ea) if isinstance(it.ea, int) else None

    def f_end(self, it: Item, ctx: Ctx) -> Any:
        if it.end is not None:
            return A(it.end)
        if isinstance(it.ea, int):
            return A(ida_bytes.get_item_end(it.ea))
        return None

    def f_size(self, it: Item, ctx: Ctx) -> Any:
        end = self.get(it, "end", ctx)
        if isinstance(it.ea, int) and end is not None:
            return int(end) - it.ea
        return None

    def f_kind(self, it: Item, ctx: Ctx) -> str:
        return self.record

    def f_name(self, it: Item, ctx: Ctx) -> str | None:
        if not isinstance(it.ea, int):
            return None
        return ida_name.get_name(it.ea) or None

    def f_demangled(self, it: Item, ctx: Ctx) -> str | None:
        n = self.get(it, "name", ctx)
        if not n:
            return None
        return ida_name.demangle_name(n, ida_name.MNG_SHORT_FORM) or n

    def f_mangled(self, it: Item, ctx: Ctx) -> str | None:
        return self.get(it, "name", ctx)

    def f_segment(self, it: Item, ctx: Ctx) -> str | None:
        if not isinstance(it.ea, int):
            return None
        seg = ida_segment.getseg(it.ea)
        return ida_segment.get_segm_name(seg) if seg else None

    def f_func(self, it: Item, ctx: Ctx) -> str | None:
        """Name of the owning function."""
        if not isinstance(it.ea, int):
            return None
        f = ida_funcs.get_func(it.ea)
        return ida_funcs.get_func_name(f.start_ea) if f else None

    def f_func_ea(self, it: Item, ctx: Ctx) -> Any:
        if not isinstance(it.ea, int):
            return None
        f = ida_funcs.get_func(it.ea)
        return A(f.start_ea) if f else None

    def f_comment(self, it: Item, ctx: Ctx) -> str | None:
        return ida_bytes.get_cmt(it.ea, False) if isinstance(it.ea, int) else None

    def f_rcomment(self, it: Item, ctx: Ctx) -> str | None:
        return ida_bytes.get_cmt(it.ea, True) if isinstance(it.ea, int) else None

    def f_flags(self, it: Item, ctx: Ctx) -> list[str]:
        return item_flags(it.ea) if isinstance(it.ea, int) else []

    def f_bytes(self, it: Item, ctx: Ctx) -> str | None:
        size = self.get(it, "size", ctx)
        if not isinstance(it.ea, int) or not size:
            return None
        data = ida_bytes.get_bytes(it.ea, min(int(size), 64)) or b""
        return data.hex()

    def f_bytes_sha256(self, it: Item, ctx: Ctx) -> str | None:
        import hashlib

        size = self.get(it, "size", ctx)
        if not isinstance(it.ea, int) or not size:
            return None
        return hashlib.sha256(ida_bytes.get_bytes(it.ea, int(size)) or b"").hexdigest()

    def f_xrefs_to(self, it: Item, ctx: Ctx) -> int | None:
        return count_xrefs_to(it.ea) if isinstance(it.ea, int) else None

    def f_xrefs_from(self, it: Item, ctx: Ctx) -> int | None:
        return count_xrefs_from(it.ea) if isinstance(it.ea, int) else None

    def f_disasm(self, it: Item, ctx: Ctx) -> str | None:
        if not isinstance(it.ea, int):
            return None
        return ida_lines.tag_remove(ida_lines.generate_disasm_line(it.ea, 0) or "")

    def f_type(self, it: Item, ctx: Ctx) -> str | None:
        if not isinstance(it.ea, int):
            return None
        from .. import typesupport

        return typesupport.type_at(it.ea)

    def f_tags(self, it: Item, ctx: Ctx) -> list[str]:
        if not isinstance(it.ea, int):
            return []
        from .. import tags

        return tags.get(it.ea)

    def f_coverage(self, it: Item, ctx: Ctx) -> int | None:
        if not isinstance(it.ea, int):
            return None
        from .. import coverage

        return coverage.hits(it.ea, self.get(it, "end", ctx))

    def f_input(self, it: Item, ctx: Ctx) -> str:
        return ida_nalt.get_root_filename() or ""

    def f_db(self, it: Item, ctx: Ctx) -> str:
        import idc

        return idc.get_idb_path() or ""

    def f_processor(self, it: Item, ctx: Ctx) -> str:
        return ida_ida.inf_get_procname()


def register(cls: type[Kind]) -> type[Kind]:
    inst = cls()
    KINDS[inst.name] = inst
    KINDS[inst.plural] = inst
    return cls


def get_kind(name: str) -> Kind:
    from ...errors import Exit, IdaxError

    kind = KINDS.get(name)
    if kind is None:
        raise IdaxError(Exit.USAGE, f"unknown kind {name!r}", "USAGE")
    return kind


# -- shared helpers -----------------------------------------------------------------


def item_flags(ea: int) -> list[str]:
    import ida_bytes as b

    f = b.get_flags(ea)
    out = []
    if b.is_code(f):
        out.append("CODE")
    elif b.is_strlit(f):
        out.append("STRLIT")
    elif b.is_struct(f):
        out.append("STRUCT")
    elif b.is_data(f):
        out.append("DATA")
    elif b.is_unknown(f):
        out.append("UNK")
    if b.has_user_name(f):
        out.append("USERNAME")
    elif b.has_dummy_name(f):
        out.append("DUMMYNAME")
    if b.has_cmt(f):
        out.append("COMMENT")
    if b.has_xref(f):
        out.append("XREF")
    return out


def count_xrefs_to(ea: int) -> int:
    import ida_xref

    n = 0
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, ida_xref.XREF_NOFLOW)
    while ok:
        n += 1
        ok = xb.next_to()
    return n


def count_xrefs_from(ea: int) -> int:
    import ida_xref

    n = 0
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, ida_xref.XREF_NOFLOW)
    while ok:
        n += 1
        ok = xb.next_from()
    return n


def compile_pattern(pattern: str, regex: bool, flags: str = "") -> Callable[[str], bool]:
    """Glob (default) or regular-expression matcher over names."""
    if regex:
        fl = 0
        for ch in flags:
            fl |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}[ch]
        rx = re.compile(pattern, fl)
        return lambda s: rx.search(s) is not None
    if pattern in ("*", ""):
        return lambda s: True
    if not any(c in pattern for c in "*?["):
        return lambda s: s == pattern
    rx = re.compile(fnmatch.translate(pattern))
    return lambda s: rx.match(s) is not None


def iter_heads(start: int, end: int) -> Iterator[int]:
    import ida_bytes as b
    import ida_idaapi

    ea = start
    if not b.is_head(b.get_flags(ea)):
        ea = b.next_head(ea, end)
    while ea != ida_idaapi.BADADDR and ea < end:
        yield ea
        ea = b.next_head(ea, end)
