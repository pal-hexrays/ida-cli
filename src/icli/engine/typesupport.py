"""Type helpers: printing, parsing and applying C declarations."""

from __future__ import annotations

import re

import ida_funcs
import ida_nalt
import ida_typeinf

from ..errors import Exit, IdaxError

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {
    "const", "volatile", "unsigned", "signed", "int", "char", "short", "long", "void", "float", "double",
    "struct", "union", "enum", "__int8", "__int16", "__int32", "__int64", "__int128", "bool", "_BOOL1",
    "_BOOL2", "_BOOL4", "_BOOL8", "__fastcall", "__cdecl", "__stdcall", "__thiscall", "__usercall",
    "__userpurge", "__noreturn", "__hidden", "__return_ptr", "__struct_ptr", "__spoils", "_BYTE", "_WORD",
    "_DWORD", "_QWORD", "_OWORD", "__pascal", "__vectorcall", "__golang", "__swiftcall", "__ptr32",
    "__ptr64", "__shifted", "__high", "__far", "__near", "__huge", "__restrict", "__unaligned",
}

PRTYPE = ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI


def tinfo_at(ea: int) -> ida_typeinf.tinfo_t | None:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        return tif
    return None


def type_at(ea: int) -> str | None:
    tif = tinfo_at(ea)
    if tif is None:
        return None
    return tif._print(None, ida_typeinf.PRTYPE_1LINE) or str(tif)


def is_user_type(ea: int) -> bool:
    return bool(ida_nalt.is_userti(ea))


def prototype(ea: int) -> str | None:
    """Function prototype with its name: ``int __fastcall main(int argc, ...)``."""
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    tif = tinfo_at(f.start_ea)
    if tif is None:
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.guess_tinfo(tif, f.start_ea):
            return None
    name = ida_funcs.get_func_name(f.start_ea) or ""
    text = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "")
    return text or str(tif)


def type_names_in(decl: str) -> list[str]:
    return [m for m in _IDENT.findall(decl or "") if m not in _KEYWORDS]


def parse_decl(decl: str, *, function: bool = False) -> tuple[ida_typeinf.tinfo_t, str]:
    """Parse one C declaration into (type, declared name)."""
    text = decl.strip()
    if not text.endswith(";"):
        text += ";"
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    name = ida_typeinf.parse_decl(tif, til, text, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP)
    if name is None:
        # an abstract type ("int (*)(void)") has no name
        name = ida_typeinf.parse_decl(tif, til, text, ida_typeinf.PT_SIL)
    if name is None or tif.empty():
        raise IdaxError(Exit.USAGE, f"cannot parse declaration: {decl!r}", "BADDECL")
    if function and not tif.is_func():
        raise IdaxError(Exit.USAGE, f"not a function prototype: {decl!r}", "BADDECL")
    return tif, name or ""


def apply_decl(ea: int, decl: str) -> bool:
    is_func = (f := ida_funcs.get_func(ea)) is not None and f.start_ea == ea
    tif, _ = parse_decl(decl)
    if is_func and not tif.is_func():
        raise IdaxError(Exit.USAGE, f"{ea:#x} is a function; {decl!r} is not a prototype", "BADDECL")
    return bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))


def clear_type(ea: int) -> bool:
    ida_nalt.del_tinfo(ea)
    return True


def decl_without_name(decl: str) -> str:
    tif, _ = parse_decl(decl)
    return str(tif)


def normalize(decl: str | None) -> str | None:
    """Canonical printed form, for idempotency comparisons."""
    if not decl:
        return None
    try:
        tif, name = parse_decl(decl)
    except IdaxError:
        return decl.strip().rstrip(";")
    return ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "") or str(tif)


# -- local types -------------------------------------------------------------------


def local_types() -> list[tuple[int, str, ida_typeinf.tinfo_t]]:
    til = ida_typeinf.get_idati()
    out = []
    for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            out.append((ordinal, tif.get_type_name() or f"#{ordinal}", tif))
    return out


def type_kind(tif: ida_typeinf.tinfo_t) -> str:
    if tif.is_struct():
        return "struct"
    if tif.is_union():
        return "union"
    if tif.is_enum():
        return "enum"
    if tif.is_func():
        return "func"
    if tif.is_typedef():
        return "typedef"
    if tif.is_ptr():
        return "pointer"
    if tif.is_array():
        return "array"
    return "other"


def type_definition(tif: ida_typeinf.tinfo_t, name: str) -> str:
    flags = ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI | \
        ida_typeinf.PRTYPE_DEF
    text = tif._print(name, flags)
    if not text:
        text = f"typedef {tif._print(None, 0)} {name};" if not tif.is_udt() else str(tif)
    return text.rstrip()


def find_local(name: str) -> ida_typeinf.tinfo_t | None:
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(ida_typeinf.get_idati(), name):
        return tif
    return None
