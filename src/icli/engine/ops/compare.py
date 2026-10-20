"""Fingerprints and annotations for ``diff`` and ``port``."""

from __future__ import annotations

import hashlib
from typing import Any

import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_nalt
import ida_segment
import ida_ua
import ida_xref

from .. import decomp, listing, select, typesupport
from ..context import Ctx
from ..kinds import KINDS
from ..kinds.annotations import comments_at
from ..kinds.base import iter_heads
from ..kinds.functions import body_hash, callees, chunks
from ..rpc import op


def _block_hash(start: int, end: int) -> str:
    h = hashlib.sha1()
    insn = ida_ua.insn_t()
    for ea in iter_heads(start, end):
        if ida_ua.decode_insn(insn, ea):
            h.update(insn.get_canon_mnem().encode())
            for o in insn.ops:
                if o.type == ida_ua.o_void:
                    break
                h.update(b"%d" % o.type)
    return h.hexdigest()[:12]


def _strings_and_constants(f: Any) -> tuple[list[str], list[int]]:
    strings: list[str] = []
    consts: set[int] = set()
    insn = ida_ua.insn_t()
    lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    for s, e in chunks(f):
        for ea in iter_heads(s, e):
            if not ida_ua.decode_insn(insn, ea):
                continue
            for o in insn.ops:
                if o.type == ida_ua.o_void:
                    break
                if o.type == ida_ua.o_imm and not (lo <= o.value < hi) and o.value > 0xFF:
                    consts.add(int(o.value))
            xb = ida_xref.xrefblk_t()
            ok = xb.first_from(ea, ida_xref.XREF_DATA)
            while ok:
                if ida_bytes.is_strlit(ida_bytes.get_flags(xb.to)):
                    t = ida_nalt.get_str_type(xb.to)
                    raw = ida_bytes.get_strlit_contents(xb.to, -1, t)
                    if raw:
                        strings.append(raw.decode("utf-8", "replace"))
                ok = xb.next_from()
    return sorted(set(strings)), sorted(consts)


@op("diff.fingerprint")
def fingerprint(ctx: Ctx, selectors: list[dict] | None = None) -> list[dict]:
    fk = KINDS["function"]
    items = list(select.functions_of(ctx, select.evaluate(ctx, selectors))) if selectors else list(fk.all(ctx))
    out = []
    for it in items:
        seg = ida_segment.getseg(it.ea)
        extern = seg is not None and seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP)
        f = it.obj
        fc = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        blocks = [_block_hash(b.start_ea, b.end_ea) for b in fc]
        edges = sum(len(list(b.succs())) for b in fc)
        strings, consts = ([], []) if extern else _strings_and_constants(f)
        fl = ida_bytes.get_flags(it.ea)
        out.append({
            "ea": it.ea, "name": ida_funcs.get_func_name(it.ea), "size": int(ida_funcs.calc_func_size(f)),
            "hash": body_hash(f), "blocks": blocks, "edges": edges,
            "insns": sum(1 for s, e in chunks(f) for _ in iter_heads(s, e)),
            "callees": [ida_funcs.get_func_name(c) or f"{c:#x}" for c in callees(f)],
            "strings": strings, "consts": consts, "extern": extern,
            "lib": bool(f.flags & ida_funcs.FUNC_LIB), "user_name": bool(ida_bytes.has_user_name(fl)),
            "dummy": not ida_bytes.has_user_name(fl), "lumina": bool(f.flags & getattr(ida_funcs, "FUNC_LUMINA", 0)),
        })
    return out


@op("diff.text")
def text(ctx: Ctx, eas: list[int], kind: str = "pseudocode") -> list[dict]:
    """Pseudocode, or disassembly normalised for diffing (no addresses)."""
    out = []
    for ea in eas:
        if kind == "pseudocode":
            r = decomp.decompile(ea) if decomp.available() else None
            body = r.text if r is not None and r.ok else f"// decompilation failed: {r.message if r else 'n/a'}"
        else:
            f = ida_funcs.get_func(ea)
            lines = []
            for s, e in chunks(f):
                for h in iter_heads(s, e):
                    lines.append(listing.instruction_text(h))
            body = "\n".join(lines)
        out.append({"ea": ea, "text": body})
    return out


@op("diff.annotations")
def annotations(ctx: Ctx, eas: list[int], what: list[str]) -> list[dict]:
    """User annotations of functions, relative to their start (for port)."""
    import ida_name

    from .. import tags as tagstore

    out = []
    for ea in eas:
        f = ida_funcs.get_func(ea)
        if f is None:
            continue
        rec: dict[str, Any] = {"ea": ea, "size": int(ida_funcs.calc_func_size(f))}
        fl = ida_bytes.get_flags(ea)
        if "names" in what and ida_bytes.has_user_name(fl) and not ida_bytes.has_auto_name(fl):
            rec["name"] = ida_name.get_name(ea)
        if "types" in what and ida_nalt.is_userti(ea):
            rec["type"] = typesupport.prototype(ea)
        if "comments" in what:
            fc = ida_funcs.get_func_cmt(f, False)
            if fc:
                rec["function_comment"] = fc
            cm = []
            first = ida_ida.inf_get_min_ea()
            for s, e in chunks(f):
                for h in iter_heads(s, e):
                    for kind, txt in comments_at(h).items():
                        if kind not in ("regular", "repeatable", "anterior", "posterior"):
                            continue
                        if kind in ("anterior", "posterior") and h == first:
                            continue  # the listing's file header, not an annotation
                        cm.append({"off": h - ea, "kind": kind, "text": txt})
            if cm:
                rec["comments"] = cm
        if "tags" in what:
            t = tagstore.get(ea)
            if t:
                rec["tags"] = t
        out.append(rec)
    return out
