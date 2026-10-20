"""Functions and their basic blocks."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_name
import ida_ua
import ida_xref

from ..context import A, Ctx
from .base import Item, Kind, iter_heads, register

FLAG_NAMES = [
    ("NORET", ida_funcs.FUNC_NORET), ("FAR", ida_funcs.FUNC_FAR), ("LIB", ida_funcs.FUNC_LIB),
    ("STATIC", ida_funcs.FUNC_STATICDEF), ("FRAME", ida_funcs.FUNC_FRAME),
    ("HIDDEN", ida_funcs.FUNC_HIDDEN), ("THUNK", ida_funcs.FUNC_THUNK),
    ("BOTTOMBP", ida_funcs.FUNC_BOTTOMBP), ("FUZZY_SP", ida_funcs.FUNC_FUZZY_SP),
    ("OUTLINE", getattr(ida_funcs, "FUNC_OUTLINE", 0)), ("LUMINA", getattr(ida_funcs, "FUNC_LUMINA", 0)),
]
FLAG_BITS = {name.lower(): bit for name, bit in FLAG_NAMES if bit}
FLAG_BITS["static"] = ida_funcs.FUNC_STATICDEF


def chunks(f: Any) -> list[tuple[int, int]]:
    out = []
    it = ida_funcs.func_tail_iterator_t(f)
    ok = it.main()
    while ok:
        c = it.chunk()
        out.append((c.start_ea, c.end_ea))
        ok = it.next()
    return out or [(f.start_ea, f.end_ea)]


def func_heads(f: Any) -> Iterable[int]:
    for start, end in chunks(f):
        for ea in iter_heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                yield ea


def body_hash(f: Any) -> str:
    """Operand-agnostic hash: mnemonics and operand *types* only, so it
    survives relocation and rebuilds that only move addresses."""
    h = hashlib.sha256()
    insn = ida_ua.insn_t()
    for ea in func_heads(f):
        if not ida_ua.decode_insn(insn, ea):
            continue
        h.update(insn.get_canon_mnem().encode())
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            h.update(b"|%d" % op.type)
            if op.type in (ida_ua.o_reg,):
                h.update(b":%d" % op.reg)
        h.update(b";")
    return h.hexdigest()


def flowchart(f: Any) -> Any:
    return ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)


def callees(f: Any) -> list[int]:
    """Distinct targets called (or tail-jumped to) from the function."""
    out: dict[int, None] = {}
    for ea in func_heads(f):
        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(ea, ida_xref.XREF_NOFLOW)
        while ok:
            to = xb.to
            if xb.iscode:
                if xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    out.setdefault(_target(to), None)
                elif xb.type in (ida_xref.fl_JN, ida_xref.fl_JF):
                    g = ida_funcs.get_func(to)
                    if g is not None and g.start_ea == to and not ida_funcs.func_contains(f, to):
                        out.setdefault(to, None)
            else:
                # indirect calls through import slots: call ds:__imp_X
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea) and _is_call(insn) and _is_import(to):
                    out.setdefault(to, None)
            ok = xb.next_from()
    return list(out)


def _target(ea: int) -> int:
    g = ida_funcs.get_func(ea)
    return g.start_ea if g is not None else ea


def _is_call(insn: Any) -> bool:
    import ida_idp

    return bool(ida_idp.is_call_insn(insn))


_import_eas: set[int] | None = None


def _is_import(ea: int) -> bool:
    global _import_eas
    if _import_eas is None:
        import ida_nalt

        found: set[int] = set()

        def cb(ea: int, name: str, ordinal: int) -> bool:
            found.add(ea)
            return True

        for i in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(i, cb)
        _import_eas = found
    return ea in _import_eas


def callers(ea: int) -> list[int]:
    """Distinct functions referencing ``ea`` by code (or by data, for
    import slots and function pointers)."""
    out: dict[int, None] = {}
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, ida_xref.XREF_NOFLOW)
    while ok:
        g = ida_funcs.get_func(xb.frm)
        if g is not None and not (xb.iscode and xb.type == ida_xref.fl_F):
            out.setdefault(g.start_ea, None)
        ok = xb.next_to()
    return list(out)


@register
class Functions(Kind):
    name = "function"
    plural = "functions"
    record = "function"
    defaults = ["ea", "name", "size", "flags"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_funcs.get_func_qty()):
            f = ida_funcs.getn_func(i)
            if f is not None:
                yield Item(self, f.start_ea, f)

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        f = ida_funcs.get_func(ea)
        return Item(self, f.start_ea, f) if f is not None else None

    def f_end(self, it: Item, ctx: Ctx) -> Any:
        return A(it.obj.end_ea)

    def f_size(self, it: Item, ctx: Ctx) -> int:
        return int(ida_funcs.calc_func_size(it.obj))

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return ida_funcs.get_func_name(it.ea) or ""

    def f_demangled(self, it: Item, ctx: Ctx) -> str:
        n = self.get(it, "name", ctx)
        return ida_name.demangle_name(n, ida_name.MNG_SHORT_FORM) or n

    def f_type(self, it: Item, ctx: Ctx) -> str | None:
        from .. import typesupport

        return typesupport.prototype(it.ea)

    def f_flags(self, it: Item, ctx: Ctx) -> list[str]:
        fl = it.obj.flags
        return [name for name, bit in FLAG_NAMES if bit and fl & bit]

    def f_lib(self, it: Item, ctx: Ctx) -> bool:
        return bool(it.obj.flags & ida_funcs.FUNC_LIB)

    def f_thunk(self, it: Item, ctx: Ctx) -> bool:
        return bool(it.obj.flags & ida_funcs.FUNC_THUNK)

    def f_noret(self, it: Item, ctx: Ctx) -> bool:
        return bool(it.obj.flags & ida_funcs.FUNC_NORET)

    def f_dummy(self, it: Item, ctx: Ctx) -> bool:
        fl = ida_bytes.get_flags(it.ea)
        return not ida_bytes.has_user_name(fl) and not (it.obj.flags & ida_funcs.FUNC_LIB) and (
            ida_bytes.has_dummy_name(fl) or not ida_bytes.has_name(fl)
        )

    def f_named(self, it: Item, ctx: Ctx) -> bool:
        return bool(ida_bytes.has_user_name(ida_bytes.get_flags(it.ea)))

    def f_xrefs_to(self, it: Item, ctx: Ctx) -> int:
        from .base import count_xrefs_to

        return count_xrefs_to(it.ea)

    def f_xrefs_from(self, it: Item, ctx: Ctx) -> int:
        from .base import count_xrefs_from

        return sum(count_xrefs_from(ea) for ea in func_heads(it.obj))

    def f_callers(self, it: Item, ctx: Ctx) -> int:
        return len(callers(it.ea))

    def f_callees(self, it: Item, ctx: Ctx) -> int:
        return len(callees(it.obj))

    def f_caller_names(self, it: Item, ctx: Ctx) -> list[str]:
        return [ida_funcs.get_func_name(ea) or f"{ea:#x}" for ea in callers(it.ea)]

    def f_callee_names(self, it: Item, ctx: Ctx) -> list[str]:
        return [ida_name.get_name(ea) or f"{ea:#x}" for ea in callees(it.obj)]

    def f_blocks(self, it: Item, ctx: Ctx) -> int:
        return flowchart(it.obj).size

    def f_insns(self, it: Item, ctx: Ctx) -> int:
        return sum(1 for _ in func_heads(it.obj))

    def f_cyclomatic(self, it: Item, ctx: Ctx) -> int:
        fc = flowchart(it.obj)
        edges = sum(len(list(b.succs())) for b in fc)
        return edges - fc.size + 2

    def f_hash(self, it: Item, ctx: Ctx) -> str:
        return body_hash(it.obj)

    def f_bytes(self, it: Item, ctx: Ctx) -> str:
        return (ida_bytes.get_bytes(it.ea, min(it.obj.end_ea - it.ea, 64)) or b"").hex()

    def f_bytes_sha256(self, it: Item, ctx: Ctx) -> str:
        h = hashlib.sha256()
        for start, end in chunks(it.obj):
            h.update(ida_bytes.get_bytes(start, end - start) or b"")
        return h.hexdigest()

    def f_chunks(self, it: Item, ctx: Ctx) -> list[dict]:
        return [{"start": A(s), "end": A(e)} for s, e in chunks(it.obj)]

    def f_frame_size(self, it: Item, ctx: Ctx) -> int:
        return int(ida_funcs.get_frame_size(it.obj)) if hasattr(ida_funcs, "get_frame_size") else int(
            it.obj.frsize)

    def f_comment(self, it: Item, ctx: Ctx) -> str | None:
        return ida_funcs.get_func_cmt(it.obj, False) or None

    def f_rcomment(self, it: Item, ctx: Ctx) -> str | None:
        return ida_funcs.get_func_cmt(it.obj, True) or None

    def f_flirt(self, it: Item, ctx: Ctx) -> str | None:
        if not it.obj.flags & ida_funcs.FUNC_LIB:
            return None
        from .types import applied_signatures

        sigs = [s["name"] for s in applied_signatures() if s.get("matches")]
        return sigs[0] if len(sigs) == 1 else ("flirt" if not sigs else ",".join(sigs))

    def f_lumina(self, it: Item, ctx: Ctx) -> str:
        bit = getattr(ida_funcs, "FUNC_LUMINA", 0)
        return "pulled" if bit and it.obj.flags & bit else "none"

    def f_pseudocode(self, it: Item, ctx: Ctx) -> str | None:
        from .. import decomp

        r = decomp.decompile(it.ea)
        return r.text if r.ok else None

    def f_hexrays_err(self, it: Item, ctx: Ctx) -> int | None:
        """Decompiler error code (0 = ok); null for import stubs, which
        are not code to decompile."""
        import ida_segment

        from .. import decomp

        seg = ida_segment.getseg(it.ea)
        if seg is not None and seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP):
            return None
        return decomp.decompile(it.ea).err

    def f_hexrays_msg(self, it: Item, ctx: Ctx) -> str | None:
        from .. import decomp

        r = decomp.decompile(it.ea)
        return r.message or None

    def f_lvars(self, it: Item, ctx: Ctx) -> int | None:
        from .. import decomp

        r = decomp.decompile(it.ea)
        return len(r.cfunc.get_lvars()) if r.ok else None

    def f_microcode(self, it: Item, ctx: Ctx) -> str | None:
        from .. import decomp

        return decomp.microcode(it.ea, ctx.opts.maturity)

    def f_disasm(self, it: Item, ctx: Ctx) -> str:
        import ida_lines

        return "\n".join(ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
                         for ea in func_heads(it.obj))

    def f_coverage(self, it: Item, ctx: Ctx) -> int:
        from .. import coverage

        return sum(coverage.hits(s, e) for s, e in chunks(it.obj))


@register
class Blocks(Kind):
    name = "block"
    plural = "blocks"
    record = "block"
    defaults = ["ea", "end", "size", "func", "succs", "preds"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for fi in KINDS_functions().all(ctx):
            yield from self.of_function(fi.obj)

    def of_function(self, f: Any) -> Iterable[Item]:
        for b in flowchart(f):
            yield Item(self, b.start_ea, b, end=b.end_ea, key=("block", b.start_ea))

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        f = ida_funcs.get_func(ea)
        if f is None:
            return None
        for b in flowchart(f):
            if b.start_ea <= ea < b.end_ea:
                return Item(self, b.start_ea, b, end=b.end_ea, key=("block", b.start_ea))
        return None

    def f_id(self, it: Item, ctx: Ctx) -> int:
        return it.obj.id

    def f_succs(self, it: Item, ctx: Ctx) -> list:
        return [A(s.start_ea) for s in it.obj.succs()]

    def f_preds(self, it: Item, ctx: Ctx) -> list:
        return [A(p.start_ea) for p in it.obj.preds()]

    def f_insns(self, it: Item, ctx: Ctx) -> int:
        return sum(1 for _ in iter_heads(it.ea, it.end or it.ea))

    def f_type(self, it: Item, ctx: Ctx) -> str:
        t = it.obj.type
        return {ida_gdl.fcb_normal: "normal", ida_gdl.fcb_indjump: "indjump", ida_gdl.fcb_ret: "ret",
                ida_gdl.fcb_cndret: "cndret", ida_gdl.fcb_noret: "noret", ida_gdl.fcb_enoret: "enoret",
                ida_gdl.fcb_extern: "extern", ida_gdl.fcb_error: "error"}.get(t, str(t))


def KINDS_functions() -> Functions:  # noqa: N802 - accessor for the registered instance
    from .base import KINDS

    return KINDS["function"]  # type: ignore[return-value]


BADADDR = ida_idaapi.BADADDR
