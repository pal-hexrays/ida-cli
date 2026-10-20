"""Plain addresses, ranges, foreign records, xrefs, local variables, switches."""

from __future__ import annotations

from typing import Any, Iterable

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_segment
import ida_xref

from ..context import A, Ctx
from .base import Item, Kind, iter_heads, register

BADADDR = ida_idaapi.BADADDR


@register
class Addresses(Kind):
    name = "address"
    plural = "addresses"
    record = "address"
    defaults = ["ea", "name", "segment", "func"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            for ea in iter_heads(s.start_ea, s.end_ea):
                yield Item(self, ea)

    def f_item(self, it: Item, ctx: Ctx) -> str:
        f = ida_bytes.get_flags(it.ea)
        if ida_bytes.is_code(f):
            return "code"
        if ida_bytes.is_strlit(f):
            return "string"
        if ida_bytes.is_struct(f):
            return "struct"
        if ida_bytes.is_data(f):
            return "data"
        if ida_bytes.is_tail(f):
            return "tail"
        return "unknown"

    def f_end(self, it: Item, ctx: Ctx) -> Any:
        return A(ida_bytes.get_item_end(it.ea))

    def f_value(self, it: Item, ctx: Ctx) -> Any:
        f = ida_bytes.get_flags(it.ea)
        if ida_bytes.is_strlit(f):
            s = ctx.db.strings.get_at(it.ea)
            return str(s) if s else None
        size = ida_bytes.get_item_size(it.ea)
        if ida_bytes.is_data(f) and size in (1, 2, 4, 8):
            return {1: ida_bytes.get_byte, 2: ida_bytes.get_word, 4: ida_bytes.get_dword,
                    8: ida_bytes.get_qword}[size](it.ea)
        return None


@register
class Ranges(Addresses):
    name = "range"
    plural = "ranges"
    record = "range"
    defaults = ["ea", "end", "size"]

    def f_end(self, it: Item, ctx: Ctx) -> Any:
        return A(it.end)


@register
class Records(Addresses):
    """Records read from standard input, a file, or the previous step (%)."""

    name = "record"
    plural = "records"
    record = "record"
    defaults = ["ea"]

    def to_record(self, it: Item, ctx: Ctx, fields: list[str] | None = None) -> dict:
        if fields:
            return {"_t": it.record.get("_t", "record"), **{f: self.get(it, f, ctx) for f in fields}}
        rec = dict(it.record or {})
        rec.setdefault("_t", "record")
        return rec

    def get(self, it: Item, name: str, ctx: Ctx) -> Any:
        if it.record is not None and name in it.record:
            return it.record[name]
        if it.ea is None:
            return None
        return super().get(it, name, ctx)


_XTYPES = {
    ida_xref.fl_CF: "call", ida_xref.fl_CN: "call", ida_xref.fl_JF: "jump", ida_xref.fl_JN: "jump",
    ida_xref.fl_F: "flow", ida_xref.dr_R: "read", ida_xref.dr_W: "write", ida_xref.dr_O: "offset",
    ida_xref.dr_T: "text", ida_xref.dr_I: "info", getattr(ida_xref, "fl_USobsolete", -99): "flow",
}
XREF_TYPES = sorted(set(_XTYPES.values()))


def xref_type(xb: Any) -> str:
    return _XTYPES.get(xb.type, "info" if not xb.iscode else "flow")


@register
class Xrefs(Kind):
    name = "xref"
    plural = "xrefs"
    record = "xref"
    defaults = ["from", "to", "type", "func_from", "func_to", "user"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            for ea in iter_heads(s.start_ea, s.end_ea):
                yield from self.from_ea(ea)

    def make(self, frm: int, to: int, xb: Any) -> Item:
        t = xref_type(xb)
        user = bool(xb.user)
        return Item(self, frm, {"from": frm, "to": to, "type": t, "user": user, "iscode": bool(xb.iscode)},
                    key=("xref", frm, to, t))

    def from_ea(self, ea: int, flow: bool = False) -> Iterable[Item]:
        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(ea, ida_xref.XREF_ALL if flow else ida_xref.XREF_NOFLOW)
        while ok:
            yield self.make(ea, xb.to, xb)
            ok = xb.next_from()

    def to_ea(self, ea: int, flow: bool = False) -> Iterable[Item]:
        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(ea, ida_xref.XREF_ALL if flow else ida_xref.XREF_NOFLOW)
        while ok:
            yield self.make(xb.frm, ea, xb)
            ok = xb.next_to()

    def f_from(self, it: Item, ctx: Ctx) -> Any:
        return A(it.obj["from"])

    def f_to(self, it: Item, ctx: Ctx) -> Any:
        return A(it.obj["to"])

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return it.obj["type"]

    def f_user(self, it: Item, ctx: Ctx) -> bool:
        return it.obj["user"]

    def f_code(self, it: Item, ctx: Ctx) -> bool:
        return it.obj["iscode"]

    def f_func_from(self, it: Item, ctx: Ctx) -> str | None:
        f = ida_funcs.get_func(it.obj["from"])
        return ida_funcs.get_func_name(f.start_ea) if f else None

    def f_func_to(self, it: Item, ctx: Ctx) -> str | None:
        f = ida_funcs.get_func(it.obj["to"])
        return ida_funcs.get_func_name(f.start_ea) if f else None

    def f_name_to(self, it: Item, ctx: Ctx) -> str | None:
        return ida_name.get_name(it.obj["to"]) or None

    def f_name_from(self, it: Item, ctx: Ctx) -> str | None:
        return ida_name.get_name(it.obj["from"]) or None

    def f_name(self, it: Item, ctx: Ctx) -> str | None:
        return self.get(it, "name_to", ctx)

    def f_disasm(self, it: Item, ctx: Ctx) -> str:
        import ida_lines

        return ida_lines.tag_remove(ida_lines.generate_disasm_line(it.obj["from"], 0) or "")


@register
class Lvars(Kind):
    name = "lvar"
    plural = "lvars"
    record = "lvar"
    defaults = ["func", "name", "type", "storage", "arg"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        from .base import KINDS

        for fi in KINDS["function"].all(ctx):
            yield from self.of_function(ctx, fi.ea)

    def of_function(self, ctx: Ctx, ea: int) -> Iterable[Item]:
        from .. import decomp

        r = decomp.decompile(ea)
        if not r.ok:
            return
        for idx, lv in enumerate(r.cfunc.get_lvars()):
            yield Item(self, r.ea, {"lv": lv, "idx": idx, "func": r.ea}, key=("lvar", r.ea, idx))

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj["lv"].name

    def f_func(self, it: Item, ctx: Ctx) -> str:
        return ida_funcs.get_func_name(it.obj["func"]) or ""

    def f_index(self, it: Item, ctx: Ctx) -> int:
        return it.obj["idx"]

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return str(it.obj["lv"].type())

    def f_size(self, it: Item, ctx: Ctx) -> int:
        return int(it.obj["lv"].width)

    def f_arg(self, it: Item, ctx: Ctx) -> bool:
        return bool(it.obj["lv"].is_arg_var)

    def f_user(self, it: Item, ctx: Ctx) -> bool:
        lv = it.obj["lv"]
        return bool(lv.has_user_name or lv.has_user_type)

    def f_storage(self, it: Item, ctx: Ctx) -> str:
        lv = it.obj["lv"]
        if lv.is_stk_var():
            return f"stack:{lv.get_stkoff():#x}"
        if lv.is_reg_var():
            import ida_hexrays

            try:
                return "reg:" + ida_hexrays.get_mreg_name(lv.get_reg1(), lv.width)
            except Exception:
                return f"reg:{lv.get_reg1()}"
        return "other"

    def f_comment(self, it: Item, ctx: Ctx) -> str | None:
        return it.obj["lv"].cmt or None

    def f_tags(self, it: Item, ctx: Ctx) -> list:
        return []


@register
class Switches(Kind):
    name = "switch"
    plural = "switches"
    record = "switch"
    defaults = ["ea", "func", "ncases", "jumptable", "default", "targets"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        from .base import KINDS
        from .functions import func_heads

        for fi in KINDS["function"].all(ctx):
            for ea in func_heads(fi.obj):
                si = ida_nalt.switch_info_t()
                if ida_nalt.get_switch_info(si, ea) is not None:
                    yield Item(self, ea, si, key=("switch", ea))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        si = ida_nalt.switch_info_t()
        return Item(self, ea, si, key=("switch", ea)) if ida_nalt.get_switch_info(si, ea) else None

    def f_ncases(self, it: Item, ctx: Ctx) -> int:
        return int(it.obj.get_jtable_size())

    def f_jumptable(self, it: Item, ctx: Ctx) -> Any:
        return A(it.obj.jumps)

    def f_default(self, it: Item, ctx: Ctx) -> Any:
        d = it.obj.defjump
        return A(d) if d not in (BADADDR, 0) else None

    def f_lowcase(self, it: Item, ctx: Ctx) -> int:
        return int(it.obj.lowcase)

    def f_targets(self, it: Item, ctx: Ctx) -> list:
        import ida_xref as x

        out: dict[int, None] = {}
        xb = x.xrefblk_t()
        ok = xb.first_from(it.ea, x.XREF_NOFLOW)
        while ok:
            if xb.iscode:
                out.setdefault(xb.to, None)
            ok = xb.next_from()
        return [A(t) for t in out]


def bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
