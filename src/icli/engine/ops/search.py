"""search: bytes, immediates, instruction patterns, listing text, pseudocode,
string literals, crypto constants."""

from __future__ import annotations

import re
from typing import Any

import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_ua

from ...errors import Exit, IcliError
from .. import decomp, listing, search as srch
from ..context import A, Ctx
from ..kinds import KINDS, compile_pattern
from ..kinds.base import iter_heads
from ..rpc import op
from .common import spans
from ..select import evaluate


def _ranges(ctx: Ctx, selectors: list[dict] | None) -> list[tuple[int, int]]:
    if not selectors:
        return [(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())]
    sel = evaluate(ctx, selectors)
    if not len(sel):
        ctx.warn("NOMATCH", "selector matched nothing")
    return spans(sel)


def _func_name(ea: int) -> str | None:
    f = ida_funcs.get_func(ea)
    return ida_funcs.get_func_name(f.start_ea) if f else None


def _hit(ea: int, **extra: Any) -> dict:
    return {"_t": "match", "ea": A(ea), "name": ida_name.get_name(ea) or None, "func": _func_name(ea), **extra}


def _refs(ea: int) -> list[str]:
    from ..kinds.program import _referencing_functions

    return [ida_funcs.get_func_name(f) for f in _referencing_functions(ea)]


def _code_heads(ranges: list[tuple[int, int]]):
    for s, e in ranges:
        for ea in iter_heads(s, e):
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                yield ea


@op("search")
def search(ctx: Ctx, mode: str, value: Any = None, selectors: list[dict] | None = None,
           limit: int | None = None) -> Any:
    ranges = _ranges(ctx, selectors)
    out: list[dict] = []

    def full() -> bool:
        return limit is not None and len(out) >= limit

    if mode == "bytes":
        for s, e in ranges:
            for ea in srch.find_bytes(value, s, e):
                out.append(_hit(ea, pattern=value))
                if full():
                    break
    elif mode == "imm":
        want = int(value)
        insn = ida_ua.insn_t()
        mask = (1 << (64 if ida_ida.inf_is_64bit() else 32)) - 1
        for ea in _code_heads(ranges):
            if not ida_ua.decode_insn(insn, ea):
                continue
            for i, opnd in enumerate(insn.ops):
                if opnd.type == ida_ua.o_void:
                    break
                vals = []
                if opnd.type == ida_ua.o_imm:
                    vals.append(opnd.value)
                if opnd.type in (ida_ua.o_displ, ida_ua.o_mem):
                    vals.append(opnd.addr)
                if any((v & mask) == (want & mask) for v in vals):
                    out.append(_hit(ea, operand=i, disasm=listing.instruction_text(ea)))
                    break
            if full():
                break
    elif mode == "insn":
        match = compile_pattern(" ".join(value.split()), False)
        for ea in _code_heads(ranges):
            text = " ".join(listing.instruction_text(ea).split())
            if match(text) or match(text.replace(", ", ",")):
                out.append(_hit(ea, disasm=text))
                if full():
                    break
    elif mode == "text":
        rx = _rx(value)
        for s, e in ranges:
            for ea in iter_heads(s, e):
                for _, line in listing.item_lines(ea):
                    if rx.search(line):
                        out.append(_hit(ea, text=line.strip()))
                        break
                if full():
                    break
    elif mode == "pseudo":
        decomp.require()
        rx = _rx(value)
        from .decompile import line_addresses

        fk = KINDS["function"]
        seen = set()
        for s, e in ranges:
            for fi in fk.all(ctx):
                if fi.ea in seen or not (s <= fi.ea < e):
                    continue
                seen.add(fi.ea)
                r = decomp.decompile(fi.ea)
                if not r.ok:
                    continue
                mapping = line_addresses(r.cfunc)
                for i, line in enumerate(r.text.split("\n")):
                    if rx.search(line):
                        eas = mapping[i] if i < len(mapping) else []
                        rec = _hit(eas[0] if eas else fi.ea, line=i + 1, text=line.strip())
                        rec["func"] = ida_funcs.get_func_name(fi.ea)
                        out.append(rec)
                if full():
                    break
    elif mode == "string":
        rx = _rx(value)
        sk = KINDS["string"]
        for it in sk.all(ctx):
            if not any(s <= it.ea < e for s, e in ranges):
                continue
            v = sk.get(it, "value", ctx)
            if rx.search(v or ""):
                refs = _refs(it.ea)
                out.append({"_t": "string", "ea": A(it.ea), "value": v, "encoding": sk.get(it, "encoding", ctx),
                            "funcs": refs, "xrefs_to": sk.get(it, "xrefs_to", ctx)})
                if full():
                    break
    elif mode == "crypto":
        for name, data in srch.CRYPTO:
            for s, e in ranges:
                for ea in srch.find_raw(data, s, e):
                    out.append({"_t": "crypto", "ea": A(ea), "name": name, "size": len(data),
                                "label": ida_name.get_name(ea) or None, "refs": _refs(ea), "func": _func_name(ea)})
        insn = ida_ua.insn_t()
        for ea in _code_heads(ranges):
            if not ida_ua.decode_insn(insn, ea):
                continue
            for opnd in insn.ops:
                if opnd.type == ida_ua.o_void:
                    break
                if opnd.type == ida_ua.o_imm and (opnd.value & 0xFFFFFFFF) in srch.CRYPTO_IMMEDIATES:
                    out.append({"_t": "crypto", "ea": A(ea), "name": srch.CRYPTO_IMMEDIATES[opnd.value & 0xFFFFFFFF],
                                "size": 4, "label": None, "refs": [_func_name(ea)] if _func_name(ea) else [],
                                "func": _func_name(ea)})
                    break
        out.sort(key=lambda r: int(r["ea"]))
    else:
        raise IcliError(Exit.USAGE, f"unknown search mode {mode!r}", "USAGE")
    if not out:
        ctx.set_status(Exit.NEGATIVE)
    return out[:limit] if limit is not None else out


def _rx(text: str) -> "re.Pattern[str]":
    try:
        return re.compile(text)
    except re.error as error:
        raise IcliError(Exit.USAGE, f"bad regular expression {text!r}: {error}", "USAGE")
