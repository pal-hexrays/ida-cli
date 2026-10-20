"""Listing lines: disassembly with optional bytes, comments and xrefs."""

from __future__ import annotations

from typing import Iterator

import ida_bytes
import ida_ida
import ida_idp
import ida_lines
import ida_segment
import ida_ua

from .addresses import format_address

_COMMENT_COLORS = (ida_lines.SCOLOR_REGCMT, ida_lines.SCOLOR_RPTCMT, ida_lines.SCOLOR_AUTOCMT)


def strip_comments(tagged: str) -> str:
    """Remove comment-coloured spans from a tagged line."""
    out: list[str] = []
    i = 0
    depth = 0
    n = len(tagged)
    while i < n:
        c = tagged[i]
        if c == ida_lines.SCOLOR_ON and i + 1 < n and tagged[i + 1] in _COMMENT_COLORS:
            depth += 1
            i += 2
            continue
        if c == ida_lines.SCOLOR_OFF and i + 1 < n and tagged[i + 1] in _COMMENT_COLORS and depth:
            depth -= 1
            i += 2
            continue
        if not depth:
            out.append(c)
        i += 1
    return ida_lines.tag_remove("".join(out)).rstrip()


def _extra(ea: int, base: int) -> list[str]:
    out = []
    i = 0
    while (line := ida_lines.get_extra_cmt(ea, base + i)) is not None:
        out.append(line)
        i += 1
    return out


def xref_comment(ea: int, limit: int = 3) -> str | None:
    """``; CODE XREF: main+1C, ...`` for the references to ``ea``."""
    import ida_xref

    refs: list[tuple[str, int]] = []
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, ida_xref.XREF_NOFLOW)
    while ok:
        refs.append(("CODE" if xb.iscode else "DATA", xb.frm))
        ok = xb.next_to()
    if not refs:
        return None
    kind = "CODE" if all(k == "CODE" for k, _ in refs) else "DATA" if all(k == "DATA" for k, _ in refs) else ""
    shown = [_where(frm) for _, frm in refs[:limit]]
    more = " ..." if len(refs) > limit else ""
    return f"; {kind + ' ' if kind else ''}XREF: {', '.join(shown)}{more}"


def _where(ea: int) -> str:
    import ida_funcs
    import ida_name

    f = ida_funcs.get_func(ea)
    if f is not None:
        name = ida_funcs.get_func_name(f.start_ea)
        off = ea - f.start_ea
        return f"{name}+{off:X}" if off else name
    return ida_name.get_name(ea) or f"{ea:X}"


def item_lines(ea: int, *, comments: bool = True, xrefs: bool = True) -> list[tuple[str, str]]:
    """Listing lines for the item at ``ea`` as (kind, text) pairs, kind one of
    blank, comment, label, item: anterior comments, the label (with an xref
    summary), the item itself, posterior comments."""
    import ida_funcs
    import ida_name

    from .typesupport import prototype

    out: list[tuple[str, str]] = []
    f = ida_funcs.get_func(ea)
    if f is not None and f.start_ea == ea:
        out.append(("blank", ""))
        proto = prototype(ea)
        if comments and proto:
            out.append(("comment", f"; {proto}"))
    if comments:
        out.extend(("comment", line) for line in _extra(ea, ida_lines.E_PREV))
    flags = ida_bytes.get_flags(ea)
    name = ida_name.get_name(ea) if ida_bytes.has_any_name(flags) else ""
    xc = xref_comment(ea) if xrefs else None
    if name and ida_bytes.is_code(flags):
        out.append(("label", f"{name}:" + (f"{' ' * max(1, 40 - len(name))}{xc}" if xc else "")))
        xc = None
    body = instruction_text(ea, comments=comments)
    out.append(("item", f"{body:<40} {xc}" if xc else body))
    if comments:
        out.extend(("comment", line) for line in _extra(ea, ida_lines.E_NEXT))
    return out


def render_lines(lines: list[tuple[str, str]], prefix: str = "", byte_col: str = "") -> list[str]:
    """Columns: [prefix] [bytes (item line only)] text; labels flush left,
    items and comments indented."""
    out = []
    for kind, text in lines:
        cols = [prefix] if prefix else []
        if byte_col:
            cols.append(byte_col if kind == "item" else " " * len(byte_col))
        if kind == "blank":
            out.append("  ".join(cols).rstrip())
            continue
        cols.append(text if kind == "label" else "        " + text)
        out.append("  ".join(cols).rstrip())
    return out


def instruction_text(ea: int, *, comments: bool = False) -> str:
    line = ida_lines.generate_disasm_line(ea, 0) or ""
    bare = strip_comments(line)
    if not comments:
        return bare
    full = ida_lines.tag_remove(line).rstrip()
    if full.startswith(bare) and len(full) > len(bare):
        return f"{bare:<40} {full[len(bare):].strip()}"
    return full


def operands(ea: int) -> list[dict]:
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return []
    names = {ida_ua.o_reg: "reg", ida_ua.o_mem: "mem", ida_ua.o_phrase: "phrase", ida_ua.o_displ: "displ",
             ida_ua.o_imm: "imm", ida_ua.o_far: "far", ida_ua.o_near: "near"}
    out = []
    for i, op in enumerate(insn.ops):
        if op.type == ida_ua.o_void:
            break
        text = ida_lines.tag_remove(ida_ua.print_operand(ea, i) or "")
        value = op.value if op.type == ida_ua.o_imm else (op.addr if op.type in (
            ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far, ida_ua.o_displ) else (op.reg if op.type == ida_ua.o_reg
                                                                             else None))
        out.append({"n": i, "text": text, "type": names.get(op.type, f"o_{op.type}"), "value": value})
    return out


def mnemonic(ea: int) -> str | None:
    return ida_ua.print_insn_mnem(ea) or None


def prefix(ea: int, style: str) -> str:
    if style == "hex":
        seg = ida_segment.getseg(ea)
        name = ida_segment.get_segm_name(seg) if seg else ""
        width = 16 if ida_ida.inf_is_64bit() else 8
        return f"{name}:{ea:0{width}X}" if name else f"{ea:0{width}X}"
    return format_address(ea, style)


def assemblers() -> list[str]:
    try:
        ph = ida_idp.get_ph()
        return [a.name for a in ph.assemblers] if hasattr(ph, "assemblers") else []
    except Exception:
        return []


class syntax:
    """Temporarily select an assembler dialect (``--syntax``)."""

    def __init__(self, name: str | None) -> None:
        self.name = name
        self.old: int | None = None

    def __enter__(self) -> "syntax":
        if not self.name:
            return self
        names = [n.lower() for n in assemblers()]
        want = self.name.lower()
        idx = next((i for i, n in enumerate(names) if want in n or n.startswith(want)), None)
        aliases = {"intel": "generic", "masm": "generic", "att": "at&t", "gas": "gnu"}
        if idx is None and want in aliases:
            idx = next((i for i, n in enumerate(names) if aliases[want] in n), None)
        if idx is None:
            from ..errors import Exit, IdaxError

            raise IdaxError(Exit.USAGE, f"--syntax {self.name}: not offered by this processor "
                            f"(available: {', '.join(assemblers()) or 'none'})", "USAGE")
        self.old = ida_ida.inf_get_asmtype()
        ida_ida.inf_set_asmtype(idx)
        return self

    def __exit__(self, *exc: object) -> None:
        if self.old is not None:
            ida_ida.inf_set_asmtype(self.old)


def heads_in(start: int, end: int) -> Iterator[int]:
    from .kinds.base import iter_heads

    return iter_heads(start, end)


def item_bytes(ea: int, limit: int | None = None) -> bytes:
    size = ida_bytes.get_item_size(ea)
    if limit is not None:
        size = min(size, limit)
    return ida_bytes.get_bytes(ea, size) or b""
