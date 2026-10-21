"""Edit handlers for code structure: functions, items, operands, call sites."""

from __future__ import annotations

from typing import Any

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_offset
import ida_typeinf
import ida_ua

from ..errors import Exit, IcliError
from . import typesupport
from .edits import HANDLERS, Handler, _fail
from .kinds.functions import FLAG_BITS, FLAG_NAMES

BADADDR = ida_idaapi.BADADDR


# -- functions --------------------------------------------------------------------------


def _get_func(ea: int, key: Any) -> dict | None:
    f = ida_funcs.get_func(ea)
    if f is None or f.start_ea != ea:
        return None
    return {"start": f"{f.start_ea:#x}", "end": f"{f.end_ea:#x}"}


def _set_func(ea: int, key: Any, value: Any, opts: dict) -> None:
    f = ida_funcs.get_func(ea)
    if value is None:
        if f is None or not ida_funcs.del_func(f.start_ea):
            raise _fail(f"cannot delete function at {ea:#x}")
        return
    end = int(value["end"], 16) if value.get("end") else BADADDR
    if f is not None and f.start_ea == ea:
        if end != BADADDR and end != f.end_ea and not ida_funcs.set_func_end(ea, end):
            raise _fail(f"cannot set end of function {ea:#x} to {end:#x}")
        return
    if f is not None:
        raise _fail(f"{ea:#x} is inside function {f.start_ea:#x}")
    if not ida_funcs.add_func(ea, end):
        raise _fail(f"cannot create a function at {ea:#x}", Exit.CONFLICT, "BADFUNC")
    ida_auto.auto_wait()


def _func_equal(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    return a["start"] == b["start"] and (not b.get("end") or a["end"] == b["end"])


HANDLERS["func"] = Handler(_get_func, _set_func, equal=_func_equal)


def _get_func_start(ea: int, key: Any) -> str | None:
    f = ida_funcs.get_func(ea)
    return f"{f.start_ea:#x}" if f is not None else None


def _set_func_start(ea: int, key: Any, value: Any, opts: dict) -> None:
    if ida_funcs.set_func_start(ea, int(value, 16)) != ida_funcs.MOVE_FUNC_OK:
        raise _fail(f"cannot move start of function at {ea:#x} to {value}")


HANDLERS["func_start"] = Handler(_get_func_start, _set_func_start)


def _get_flags(ea: int, key: Any) -> list[str] | None:
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    return sorted(name.lower() for name, bit in FLAG_NAMES if bit and f.flags & bit)


def _set_flags(ea: int, key: Any, value: Any, opts: dict) -> None:
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IcliError(Exit.EMPTY_SELECTION, f"no function at {ea:#x}", "NOMATCH")
    managed = 0
    for bit in FLAG_BITS.values():
        managed |= bit
    want = 0
    for name in value or []:
        want |= FLAG_BITS[name]
    f.flags = (f.flags & ~managed) | want
    if not ida_funcs.update_func(f):
        raise _fail(f"cannot update flags of function {ea:#x}")


HANDLERS["func_flags"] = Handler(_get_flags, _set_flags, equal=lambda a, b: sorted(a or []) == sorted(b or []))


def _get_tail(ea: int, key: str) -> str | None:
    start = int(key, 16)
    f = ida_funcs.get_func(ea)
    c = ida_funcs.get_fchunk(start)
    if f is None or c is None or c.start_ea != start or ida_funcs.is_func_entry(c):
        return None
    owner = ida_funcs.get_func(start)
    return f"{c.end_ea:#x}" if owner is not None and owner.start_ea == f.start_ea else None


def _set_tail(ea: int, key: str, value: Any, opts: dict) -> None:
    f = ida_funcs.get_func(ea)
    start = int(key, 16)
    if value is None:
        if not ida_funcs.remove_func_tail(f, start):
            raise _fail(f"cannot remove chunk {key} from function {f.start_ea:#x}")
        return
    if not ida_funcs.append_func_tail(f, start, int(value, 16)):
        raise _fail(f"cannot add chunk {key}..{value} to function {f.start_ea:#x}")


HANDLERS["func_tail"] = Handler(_get_tail, _set_tail)


# -- items (make) -----------------------------------------------------------------------------

_DATA_KINDS = {1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "oword", 10: "tbyte"}


def describe_item(ea: int) -> dict:
    f = ida_bytes.get_flags(ea)
    size = ida_bytes.get_item_size(ea)
    if ida_bytes.is_code(f):
        return {"kind": "code"}
    if ida_bytes.is_unknown(f):
        return {"kind": "unknown"}
    if ida_bytes.is_strlit(f):
        return {"kind": "string", "size": size, "strtype": ida_nalt.get_str_type(ea)}
    if ida_bytes.is_struct(f):
        tif = typesupport.tinfo_at(ea)
        return {"kind": "struct", "type": tif.get_type_name() if tif else None, "size": size}
    if ida_bytes.is_align(f):
        return {"kind": "align", "size": size}
    if ida_bytes.is_float(f):
        elem, base = 4, "float"
    elif ida_bytes.is_double(f):
        elem, base = 8, "double"
    else:
        elem = {ida_bytes.FF_BYTE: 1, ida_bytes.FF_WORD: 2, ida_bytes.FF_DWORD: 4, ida_bytes.FF_QWORD: 8,
                ida_bytes.FF_OWORD: 16, ida_bytes.FF_TBYTE: 10}.get(f & ida_bytes.DT_TYPE, 1)
        base = _DATA_KINDS.get(elem, "byte")
    out: dict[str, Any] = {"kind": base}
    if size > elem:
        out = {"kind": "array", "of": base, "count": size // elem}
    if ida_bytes.is_off0(f):
        out["offset"] = True
    return out


def _get_item(ea: int, key: Any) -> dict:
    return describe_item(ea)


def _item_size(value: dict) -> int:
    sizes = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "oword": 16, "tbyte": 10, "float": 4, "double": 8}
    k = value["kind"]
    if k in sizes:
        return sizes[k]
    if k == "array":
        return sizes[value["of"]] * int(value["count"])
    return int(value.get("size") or 0)


def _set_item(ea: int, key: Any, value: Any, opts: dict) -> None:
    k = value["kind"]
    size = max(_item_size(value), ida_bytes.get_item_size(ea), 1)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    ok = True
    if k == "unknown":
        return
    if k == "code":
        ok = ida_ua.create_insn(ea) > 0
        if ok and opts.get("analyse", True):
            ida_auto.auto_make_code(ea)
            ida_auto.auto_wait()
    elif k in ("byte", "word", "dword", "qword", "oword", "tbyte", "float", "double"):
        fn = {"byte": ida_bytes.create_byte, "word": ida_bytes.create_word, "dword": ida_bytes.create_dword,
              "qword": ida_bytes.create_qword, "oword": ida_bytes.create_oword, "tbyte": ida_bytes.create_tbyte,
              "float": ida_bytes.create_float, "double": ida_bytes.create_double}[k]
        ok = fn(ea, _item_size(value), True)
    elif k == "array":
        elem = _item_size({"kind": value["of"]})
        fn = {"byte": ida_bytes.create_byte, "word": ida_bytes.create_word, "dword": ida_bytes.create_dword,
              "qword": ida_bytes.create_qword, "float": ida_bytes.create_float,
              "double": ida_bytes.create_double}[value["of"]]
        ok = fn(ea, elem * int(value["count"]), True)
    elif k == "string":
        strtype = value.get("strtype", ida_nalt.STRTYPE_C)
        length = value.get("size") or 0
        ok = ida_bytes.create_strlit(ea, length, strtype)
    elif k == "struct":
        tif = typesupport.find_local(value["type"])
        if tif is None:
            raise IcliError(Exit.EMPTY_SELECTION, f"no local type {value['type']!r}", "NOMATCH")
        ok = ida_bytes.create_struct(ea, tif.get_size(), tif.get_tid(), True)
    elif k == "align":
        ok = ida_bytes.create_align(ea, int(value.get("size") or 0), 0)
    else:
        raise IcliError(Exit.USAGE, f"unknown item kind {k!r}", "USAGE")
    if not ok:
        raise _fail(f"cannot make {k} at {ea:#x}", Exit.CONFLICT, "BADITEM")
    if value.get("offset"):
        ida_offset.op_plain_offset(ea, 0, int(value.get("base") or 0))


def _item_equal(a: dict, b: dict) -> bool:
    if a.get("kind") != b.get("kind"):
        return False
    for k, v in b.items():
        if k in ("kind", "base"):
            continue
        if k == "size" and not v:
            continue
        if a.get(k) != v:
            return False
    return True


HANDLERS["item"] = Handler(_get_item, _set_item, equal=_item_equal)


# -- operand representation --------------------------------------------------------------------


def _get_operand(ea: int, key: int) -> str:
    n = int(key)
    f = ida_bytes.get_flags(ea)
    if ida_bytes.is_off(f, n):
        return "offset"
    if ida_bytes.is_enum(f, n):
        tid = ida_bytes.get_enum_id(ea, n)[0] if isinstance(ida_bytes.get_enum_id(ea, n), tuple) else \
            ida_bytes.get_enum_id(ea, n)
        t = ida_typeinf.tinfo_t()
        name = t.get_type_name() if t.get_type_by_tid(tid) else str(tid)
        return f"enum:{name}"
    if ida_bytes.is_stroff(f, n):
        return "stroff"
    if ida_bytes.is_stkvar(f, n):
        return "stkvar"
    if ida_bytes.is_char(f, n):
        return "char"
    if ida_bytes.is_numop(f, n):
        radix = ida_bytes.get_radix(f, n)
        return {16: "hex", 10: "dec", 8: "oct", 2: "bin"}.get(radix, "hex")
    return "default"


def _set_operand(ea: int, key: int, value: Any, opts: dict) -> None:
    n = int(key)
    kind, _, arg = str(value).partition(":")
    ok = True
    if kind == "default":
        ok = ida_bytes.clr_op_type(ea, n)
    elif kind == "hex":
        ok = ida_bytes.op_hex(ea, n)
    elif kind == "dec":
        ok = ida_bytes.op_dec(ea, n)
    elif kind == "oct":
        ok = ida_bytes.op_oct(ea, n)
    elif kind == "bin":
        ok = ida_bytes.op_bin(ea, n)
    elif kind == "char":
        ok = ida_bytes.op_chr(ea, n)
    elif kind == "offset":
        base = int(arg, 0) if arg else 0
        ok = ida_offset.op_plain_offset(ea, n, base)
    elif kind == "enum":
        tif = typesupport.find_local(arg)
        if tif is None or not tif.is_enum():
            raise IcliError(Exit.EMPTY_SELECTION, f"no enum {arg!r} in local types", "NOMATCH")
        ok = ida_bytes.op_enum(ea, n, tif.get_tid(), 0)
    elif kind == "stroff":
        tif = typesupport.find_local(arg)
        if tif is None or not tif.is_udt():
            raise IcliError(Exit.EMPTY_SELECTION, f"no struct {arg!r} in local types", "NOMATCH")
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
        path = ida_typeinf.tid_array(1) if hasattr(ida_typeinf, "tid_array") else None
        if path is not None:
            path[0] = tif.get_tid()
            ok = ida_bytes.op_stroff(insn, n, path.cast(), 1, 0)
        else:
            ok = ida_bytes.op_stroff(insn, n, [tif.get_tid()], 1, 0)
    elif kind == "stkvar":
        ok = ida_bytes.op_stkvar(ea, n)
    else:
        raise IcliError(Exit.USAGE, f"--as {value}: one of hex, dec, oct, bin, char, offset[:base], enum:NAME, "
                        "stroff:STRUCT, stkvar, default", "USAGE")
    if not ok:
        raise _fail(f"cannot represent operand {n} at {ea:#x} as {value}", Exit.CONFLICT, "BADOPERAND")


def _operand_equal(a: str, b: str) -> bool:
    return a == str(b).split(":", 1)[0] if a in ("offset", "stroff") else a == b


HANDLERS["operand"] = Handler(_get_operand, _set_operand, equal=_operand_equal)


# -- call-site prototypes ---------------------------------------------------------------------------


def _get_callsite(ea: int, key: Any) -> str | None:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_op_tinfo(tif, ea, 0) and tif.is_func():
        return str(tif)
    return None


def _set_callsite(ea: int, key: Any, value: Any, opts: dict) -> None:
    if not value:
        ida_nalt.del_op_tinfo(ea, 0)
        return
    tif = typesupport.parse_type(value)
    if not tif.is_func():
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
        else:
            raise IcliError(Exit.USAGE, f"{value!r} is not a function prototype", "BADDECL")
    if not ida_nalt.set_op_tinfo(ea, 0, tif):
        raise _fail(f"cannot set call type at {ea:#x}")
    ida_typeinf.apply_callee_tinfo(ea, tif)


HANDLERS["callsite"] = Handler(_get_callsite, _set_callsite,
                               equal=lambda a, b: a == b or (bool(a) and bool(b) and
                                                             typesupport.normalize(a) == typesupport.normalize(b)))
