"""Segments, names, strings, imports, exports and entry points."""

from __future__ import annotations

from typing import Iterable

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment

from ..context import A, Ctx
from .base import Item, Kind, register

BADADDR = ida_idaapi.BADADDR


@register
class Segments(Kind):
    name = "segment"
    plural = "segments"
    record = "segment"
    defaults = ["ea", "end", "size", "name", "class", "perm", "bitness"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if s is not None:
                yield Item(self, s.start_ea, s, end=s.end_ea, key=("segment", s.start_ea))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        s = ida_segment.getseg(ea)
        return Item(self, s.start_ea, s, end=s.end_ea, key=("segment", s.start_ea)) if s else None

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return ida_segment.get_segm_name(it.obj) or ""

    def f_class(self, it: Item, ctx: Ctx) -> str:
        return ida_segment.get_segm_class(it.obj) or ""

    def f_perm(self, it: Item, ctx: Ctx) -> str:
        p = it.obj.perm
        return ("r" if p & ida_segment.SEGPERM_READ else "-") + \
               ("w" if p & ida_segment.SEGPERM_WRITE else "-") + \
               ("x" if p & ida_segment.SEGPERM_EXEC else "-")

    def f_bitness(self, it: Item, ctx: Ctx) -> int:
        return {0: 16, 1: 32, 2: 64}.get(it.obj.bitness, 0)

    def f_type(self, it: Item, ctx: Ctx) -> str:
        t = it.obj.type
        names = {ida_segment.SEG_NORM: "normal", ida_segment.SEG_XTRN: "extern", ida_segment.SEG_CODE: "code",
                 ida_segment.SEG_DATA: "data", ida_segment.SEG_BSS: "bss", ida_segment.SEG_ABSSYM: "abs",
                 ida_segment.SEG_COMM: "comm", ida_segment.SEG_NULL: "null", ida_segment.SEG_UNDF: "undef",
                 ida_segment.SEG_IMP: "imp", ida_segment.SEG_IMEM: "imem", ida_segment.SEG_GRP: "group"}
        return names.get(t, str(t))

    def f_comment(self, it: Item, ctx: Ctx) -> str | None:
        return ida_segment.get_segment_cmt(it.obj, False) or None

    def f_segment(self, it: Item, ctx: Ctx) -> str:
        return self.get(it, "name", ctx)


@register
class Names(Kind):
    name = "name"
    plural = "names"
    record = "name"
    defaults = ["ea", "name", "demangled", "type"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            yield Item(self, ea, ida_name.get_nlist_name(i), key=("name", ea))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        n = ida_name.get_name(ea)
        return Item(self, ea, n, key=("name", ea)) if n else None

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj or ida_name.get_name(it.ea) or ""

    def f_type(self, it: Item, ctx: Ctx) -> str:
        """What the name labels: function, code, data, string, import."""
        f = ida_bytes.get_flags(it.ea)
        fn = ida_funcs.get_func(it.ea)
        if fn is not None and fn.start_ea == it.ea:
            return "function"
        seg = ida_segment.getseg(it.ea)
        if seg is not None and seg.type == ida_segment.SEG_XTRN:
            return "import"
        if ida_bytes.is_code(f):
            return "code"
        if ida_bytes.is_strlit(f):
            return "string"
        return "data"

    def f_public(self, it: Item, ctx: Ctx) -> bool:
        return bool(ida_name.is_public_name(it.ea))

    def f_weak(self, it: Item, ctx: Ctx) -> bool:
        return bool(ida_name.is_weak_name(it.ea))

    def f_user(self, it: Item, ctx: Ctx) -> bool:
        return bool(ida_bytes.has_user_name(ida_bytes.get_flags(it.ea)))

    def f_decl(self, it: Item, ctx: Ctx) -> str | None:
        from .. import typesupport

        return typesupport.type_at(it.ea)


def _strtype_name(t: int) -> str:
    width = ida_nalt.get_strtype_bpu(t) if hasattr(ida_nalt, "get_strtype_bpu") else 1
    return {1: "c", 2: "utf16", 4: "utf32"}.get(width, str(t))


@register
class Strings(Kind):
    name = "string"
    plural = "strings"
    record = "string"
    defaults = ["ea", "size", "encoding", "value"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for s in ctx.db.strings:
            yield Item(self, s.address, s, end=s.address + s.length, key=("string", s.address))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        s = ctx.db.strings.get_at(ea)
        return Item(self, s.address, s, end=s.address + s.length, key=("string", s.address)) if s else None

    def f_value(self, it: Item, ctx: Ctx) -> str:
        try:
            return str(it.obj)
        except Exception:
            return (it.obj.contents or b"").decode("utf-8", "replace")

    def f_length(self, it: Item, ctx: Ctx) -> int:
        return len(self.get(it, "value", ctx))

    def f_encoding(self, it: Item, ctx: Ctx) -> str:
        try:
            return it.obj.encoding or _strtype_name(it.obj.internal_type)
        except Exception:
            return _strtype_name(it.obj.internal_type)

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return _strtype_name(it.obj.internal_type)

    def f_funcs(self, it: Item, ctx: Ctx) -> list[str]:
        """Names of functions referencing the string."""
        return [ida_funcs.get_func_name(ea) for ea in _referencing_functions(it.ea)]

    def f_refs(self, it: Item, ctx: Ctx) -> list:
        return [A(ea) for ea in _referencing_functions(it.ea)]

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        return [self.get(it, "value", ctx)]


def _referencing_functions(ea: int) -> list[int]:
    import ida_xref

    out: dict[int, None] = {}
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, ida_xref.XREF_NOFLOW)
    while ok:
        f = ida_funcs.get_func(xb.frm)
        if f is not None:
            out.setdefault(f.start_ea, None)
        ok = xb.next_to()
    return list(out)


@register
class Imports(Kind):
    name = "import"
    plural = "imports"
    record = "import"
    defaults = ["ea", "module", "name", "ordinal"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_nalt.get_import_module_qty()):
            module = ida_nalt.get_import_module_name(i) or ""
            rows: list[tuple[int, str, int]] = []

            def cb(ea: int, name: str | None, ordinal: int) -> bool:
                rows.append((ea, name or "", ordinal))
                return True

            ida_nalt.enum_import_names(i, cb)
            for ea, name, ordinal in rows:
                yield Item(self, ea, {"module": module, "name": name, "ordinal": ordinal},
                           key=("import", ea))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        for it in self.all(ctx):
            if it.ea == ea:
                return it
        return None

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj["name"] or ida_name.get_name(it.ea) or ""

    def f_module(self, it: Item, ctx: Ctx) -> str:
        return it.obj["module"]

    def f_ordinal(self, it: Item, ctx: Ctx) -> int:
        return it.obj["ordinal"]

    def f_size(self, it: Item, ctx: Ctx) -> int:
        return ida_bytes.get_item_size(it.ea)


@register
class Entries(Kind):
    name = "entry"
    plural = "entries"
    record = "entry"
    defaults = ["ea", "name", "ordinal", "type"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        seen: set[int] = set()
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            if ea == BADADDR:
                continue
            seen.add(ea)
            yield Item(self, ea, {"ordinal": ordinal, "name": ida_entry.get_entry_name(ordinal),
                                  "type": "entry", "forwarder": ida_entry.get_entry_forwarder(ordinal)},
                       key=("entry", ea, ordinal))
        start = ida_ida.inf_get_start_ea()
        if start != BADADDR and start not in seen:
            seen.add(start)
            yield Item(self, start, {"ordinal": None, "name": ida_name.get_name(start), "type": "start"},
                       key=("entry", start, None))
        for ea, kind in _init_pointers():
            if ea not in seen:
                seen.add(ea)
                yield Item(self, ea, {"ordinal": None, "name": ida_name.get_name(ea), "type": kind},
                           key=("entry", ea, kind))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        return next((it for it in self.all(ctx) if it.ea == ea), None)

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj.get("name") or ida_name.get_name(it.ea) or ""

    def f_ordinal(self, it: Item, ctx: Ctx) -> int | None:
        return it.obj.get("ordinal")

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return it.obj.get("type", "entry")

    def f_forwarder(self, it: Item, ctx: Ctx) -> str | None:
        return it.obj.get("forwarder") or None


def _init_pointers() -> list[tuple[int, str]]:
    """TLS callbacks and ELF/Mach-O initialiser arrays."""
    out: list[tuple[int, str]] = []
    ptr = 8 if ida_ida.inf_is_64bit() else 4
    read = ida_bytes.get_qword if ptr == 8 else ida_bytes.get_dword
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        name = ida_segment.get_segm_name(s) or ""
        kind = None
        if name in (".init_array", "__mod_init_func", ".ctors", "__init_offsets"):
            kind = "init_array"
        if kind is None:
            continue
        for ea in range(s.start_ea, s.end_ea, ptr):
            target = read(ea)
            if ida_funcs.get_func(target) is not None:
                out.append((target, kind))
    for i in range(ida_name.get_nlist_size()):
        n = ida_name.get_nlist_name(i)
        if n.startswith("TlsCallback_"):
            out.append((ida_name.get_nlist_ea(i), "tls_callback"))
    return out


@register
class Exports(Entries):
    name = "export"
    plural = "exports"
    record = "export"
    defaults = ["ea", "name", "ordinal", "forwarder"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if ea == BADADDR or not name:
                continue
            if ea == ida_ida.inf_get_start_ea() and ordinal == ea:
                continue  # the program entry point is not an export
            yield Item(self, ea, {"ordinal": ordinal, "name": name, "type": "export",
                                  "forwarder": ida_entry.get_entry_forwarder(ordinal)},
                       key=("export", ea, ordinal))

