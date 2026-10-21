"""Address rendering (``--addr``) and address-expression evaluation."""

from __future__ import annotations

import ida_entry
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_nalt
import ida_segment

from ..errors import Exit, IcliError

BADADDR = ida_idaapi.BADADDR


def _width() -> int:
    return 16 if ida_ida.inf_is_64bit() else 8


def format_address(ea: int, style: str = "hex") -> str:
    if style == "bare":
        return f"{ea:X}"
    if style == "seg":
        seg = ida_segment.getseg(ea)
        if seg is None:
            return f"{ea:#x}"
        name = ida_segment.get_segm_name(seg) or "seg"
        base = ida_segment.get_segm_base(seg)
        return f"{name}:{ea - base:0{_width()}X}"
    if style == "rva":
        return f"rva:{ea - ida_nalt.get_imagebase():#x}"
    if style == "file":
        off = ida_loader.get_fileregion_offset(ea)
        return f"off:{off:#x}" if off is not None and off >= 0 else ""
    return f"{ea:#x}"


def entry_point() -> int:
    ea = ida_ida.inf_get_start_ea()
    if ea == BADADDR:
        if ida_entry.get_entry_qty():
            ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
    return ea


def symbol(sym: str) -> int:
    if sym == "entry":
        ea = entry_point()
    elif sym == "base":
        ea = ida_nalt.get_imagebase()
    elif sym == "min":
        ea = ida_ida.inf_get_min_ea()
    elif sym == "max":
        ea = ida_ida.inf_get_max_ea()
    else:
        raise IcliError(Exit.USAGE, f"unknown symbol ${sym}", "USAGE")
    if ea == BADADDR:
        raise IcliError(Exit.EMPTY_SELECTION, f"${sym} is not defined in this database", "NOMATCH")
    return ea


def demangled_matches(text: str) -> list[int]:
    """All named addresses whose demangled name (with or without arguments)
    equals ``text`` — every overload of ``CView::OnPaint``."""
    out = []
    short = ida_name.MNG_SHORT_FORM
    for i in range(ida_name.get_nlist_size()):
        ea = ida_name.get_nlist_ea(i)
        name = ida_name.get_nlist_name(i)
        dem = ida_name.demangle_name(name, short) if name else None
        if not dem:
            continue
        if dem == text or dem.split("(", 1)[0] == text:
            out.append(ea)
    return out


def name_to_ea(name: str) -> list[int]:
    ea = ida_name.get_name_ea(BADADDR, name)
    if ea != BADADDR:
        return [ea]
    return demangled_matches(name)


def atom(a: dict) -> list[int]:
    """Evaluate one address atom; a demangled name may denote several."""
    if "num" in a and "seg" not in a:
        return [int(a["num"])]
    if "sym" in a:
        return [symbol(a["sym"])]
    if "rva" in a:
        return [ida_nalt.get_imagebase() + int(a["rva"])]
    if "off" in a:
        ea = ida_loader.get_fileregion_ea(int(a["off"]))
        if ea == BADADDR:
            raise IcliError(Exit.EMPTY_SELECTION, f"file offset {a['off']:#x} is not loaded", "NOMATCH")
        return [ea]
    if "seg" in a:
        seg = ida_segment.get_segm_by_name(a["seg"])
        if seg is None:
            # not a segment: maybe a name containing ':' (C++ scope without quotes)
            return name_to_ea(f"{a['seg']}:{a['num']:x}")
        return [ida_segment.get_segm_base(seg) + int(a["num"])]
    if "name" in a:
        if a.get("demangled"):
            found = demangled_matches(a["name"]) or name_to_ea(a["name"])
        else:
            found = name_to_ea(a["name"])
        return found
    raise IcliError(Exit.USAGE, f"bad address atom {a!r}", "USAGE")


def evaluate(expr: dict) -> list[int]:
    """Evaluate an address expression to one or more addresses (overloads)."""
    terms = expr["terms"]
    bases = atom(terms[0][1])
    offset = 0
    for sign, a in terms[1:]:
        vals = atom(a)
        if len(vals) != 1:
            raise IcliError(Exit.USAGE, "address arithmetic needs a single-valued operand", "USAGE")
        offset += vals[0] if sign == "+" else -vals[0]
    return [b + offset for b in bases]


def describe(expr: dict) -> str:
    parts = []
    for i, (sign, a) in enumerate(expr["terms"]):
        if "name" in a:
            s = a["name"]
        elif "sym" in a:
            s = "$" + a["sym"]
        elif "seg" in a:
            s = f"{a['seg']}:{a['num']:x}"
        elif "rva" in a:
            s = f"rva:{a['rva']:#x}"
        elif "off" in a:
            s = f"off:{a['off']:#x}"
        else:
            s = f"{a['num']:#x}"
        parts.append(s if i == 0 else f"{sign}{s}")
    return "".join(parts)
