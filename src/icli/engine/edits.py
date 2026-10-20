"""Declarative edits.

Every edit is a ``change(kind, ea, key, value)``: the handler reads the
current value, does nothing when it already matches (``unchanged``), refuses
to overwrite a value set by a user unless forced (status 9), and otherwise
writes it and appends a journal record carrying before/after.  ``undo`` and
``apply`` reuse exactly the same path, so they are idempotent and journaled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_lines
import ida_name
import ida_nalt
import ida_typeinf

from ..errors import Exit, IdaxError
from . import journal, typesupport
from .context import A, Ctx

BADADDR = ida_idaapi.BADADDR


@dataclass
class Handler:
    get: Callable[[int, Any], Any]
    set: Callable[[int, Any, Any, dict], None]
    user: Callable[[int, Any, Any], bool] = lambda ea, key, before: False
    equal: Callable[[Any, Any], bool] = lambda a, b: a == b


HANDLERS: dict[str, Handler] = {}


def _fail(msg: str, status: int = Exit.CONFLICT, code: str = "CONFLICT") -> IdaxError:
    return IdaxError(status, msg, code)


# -- names -------------------------------------------------------------------------------


def _get_name(ea: int, key: Any) -> str | None:
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.has_any_name(flags) and not ida_name.get_name(ea):
        return None
    return ida_name.get_name(ea) or None


def _set_name(ea: int, key: Any, value: Any, opts: dict) -> None:
    name = value or ""
    flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK if name else ida_name.SN_NOWARN
    if opts.get("local"):
        flags |= ida_name.SN_LOCAL
    if name:
        other = ida_name.get_name_ea(BADADDR, name)
        if other != BADADDR and other != ea:
            raise _fail(f"name {name!r} is already used at {other:#x}")
        if not ida_name.is_ident(name) and not opts.get("local"):
            flags &= ~ida_name.SN_NOCHECK
    if not ida_name.set_name(ea, name, flags):
        raise _fail(f"cannot set name {name!r} at {ea:#x}", Exit.CONFLICT, "BADNAME")
    if name and opts.get("public"):
        ida_name.make_name_public(ea)
    if name and opts.get("weak"):
        ida_name.make_name_weak(ea)


def _user_name(ea: int, key: Any, before: Any) -> bool:
    """Set by a person: loader and analysis names carry the auto flag."""
    flags = ida_bytes.get_flags(ea)
    return bool(ida_bytes.has_user_name(flags)) and not ida_bytes.has_auto_name(flags)


HANDLERS["name"] = Handler(_get_name, _set_name, _user_name)


# -- comments -------------------------------------------------------------------------------

COMMENT_KINDS = ("regular", "repeatable", "anterior", "posterior", "function", "pseudocode")


def _extra_lines(ea: int, base: int) -> list[str]:
    out = []
    i = 0
    while (line := ida_lines.get_extra_cmt(ea, base + i)) is not None:
        out.append(line)
        i += 1
    return out


def _get_comment(ea: int, key: str) -> str | None:
    if key == "regular":
        return ida_bytes.get_cmt(ea, False) or None
    if key == "repeatable":
        return ida_bytes.get_cmt(ea, True) or None
    if key in ("anterior", "posterior"):
        lines = _extra_lines(ea, ida_lines.E_PREV if key == "anterior" else ida_lines.E_NEXT)
        return "\n".join(lines) if lines else None
    if key == "function":
        f = ida_funcs.get_func(ea)
        return (ida_funcs.get_func_cmt(f, False) or None) if f else None
    if key == "pseudocode":
        from . import decomp

        r = decomp.decompile(ea)
        if not r.ok:
            return None
        import ida_hexrays

        loc = ida_hexrays.treeloc_t()
        loc.ea, loc.itp = ea, ida_hexrays.ITP_SEMI
        return r.cfunc.get_user_cmt(loc, ida_hexrays.RETRIEVE_ALWAYS) or None
    raise IdaxError(Exit.USAGE, f"unknown comment kind {key!r}", "USAGE")


def _set_comment(ea: int, key: str, value: Any, opts: dict) -> None:
    text = value or ""
    if key in ("regular", "repeatable"):
        ida_bytes.set_cmt(ea, text, key == "repeatable")
    elif key in ("anterior", "posterior"):
        base = ida_lines.E_PREV if key == "anterior" else ida_lines.E_NEXT
        ida_lines.delete_extra_cmts(ea, base)
        for i, line in enumerate(text.split("\n") if text else []):
            ida_lines.update_extra_cmt(ea, base + i, line)
    elif key == "function":
        f = ida_funcs.get_func(ea)
        if f is None:
            raise IdaxError(Exit.EMPTY_SELECTION, f"no function at {ea:#x}", "NOMATCH")
        ida_funcs.set_func_cmt(f, text, False)
    elif key == "pseudocode":
        import ida_hexrays

        from . import decomp

        r = decomp.decompile(ea)
        if not r.ok:
            raise IdaxError(Exit.DECOMPILE, f"{ea:#x}: cannot decompile: {r.message}", "HEXRAYS")
        loc = ida_hexrays.treeloc_t()
        loc.ea, loc.itp = ea, ida_hexrays.ITP_SEMI
        r.cfunc.set_user_cmt(loc, text)
        r.cfunc.save_user_cmts()
        decomp.reset()


HANDLERS["comment"] = Handler(_get_comment, _set_comment)


# -- types ---------------------------------------------------------------------------------


def _get_type(ea: int, key: Any) -> str | None:
    f = ida_funcs.get_func(ea)
    if f is not None and f.start_ea == ea:
        return typesupport.prototype(ea) if typesupport.tinfo_at(ea) is not None else None
    return typesupport.type_at(ea)


def _set_type(ea: int, key: Any, value: Any, opts: dict) -> None:
    if not value:
        typesupport.clear_type(ea)
        return
    if not typesupport.apply_decl(ea, value):
        raise _fail(f"cannot apply type {value!r} at {ea:#x}", Exit.CONFLICT, "BADTYPE")
    if opts.get("rename_from_decl"):
        _, name = typesupport.parse_decl(value)
        if name and name != ida_name.get_name(ea):
            ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)


def _type_equal(a: Any, b: Any) -> bool:
    if a == b:
        return True
    if not a or not b:
        return False
    return typesupport.normalize(a) == typesupport.normalize(b) or _strip_name(a) == _strip_name(b)


def _strip_name(decl: str) -> str:
    try:
        tif, _ = typesupport.parse_decl(decl)
        return str(tif)
    except IdaxError:
        return decl


HANDLERS["type"] = Handler(_get_type, _set_type, lambda ea, key, before: typesupport.is_user_type(ea)
                           and before is not None, _type_equal)


# -- local variables (decompiler) -----------------------------------------------------------


def lvar_key(lv: Any) -> str:
    """Stable identity of a decompiler local variable: definition address
    and storage (names change; locations do not)."""
    from .decomp import lvar_storage

    return f"{lv.defea:#x}:{lvar_storage(lv)}"


def lvars(ea: int) -> list:
    from . import decomp

    r = decomp.decompile(ea)
    if not r.ok:
        raise IdaxError(Exit.DECOMPILE, f"{ea:#x}: cannot decompile: {r.message}", "HEXRAYS")
    return list(r.cfunc.get_lvars())


def find_lvar(ea: int, *, name: str | None = None, key: str | None = None) -> Any:
    for lv in lvars(ea):
        if (name is not None and lv.name == name) or (key is not None and lvar_key(lv) == key):
            return lv
    return None


def _get_lvar_name(ea: int, key: str) -> str | None:
    lv = find_lvar(ea, key=key)
    return lv.name if lv is not None else None


def _set_lvar_name(ea: int, key: str, value: Any, opts: dict) -> None:
    import ida_hexrays

    from . import decomp

    lv = find_lvar(ea, key=key)
    if lv is None:
        raise IdaxError(Exit.EMPTY_SELECTION, f"no local variable {key}", "NOMATCH")
    if any(other.name == value for other in lvars(ea) if lvar_key(other) != key):
        raise _fail(f"local variable name {value!r} is already used")
    if not ida_hexrays.rename_lvar(ida_funcs.get_func(ea).start_ea, lv.name, value):
        raise _fail(f"cannot rename local variable {lv.name!r} to {value!r}")
    decomp.reset()


HANDLERS["lvar_name"] = Handler(_get_lvar_name, _set_lvar_name,
                                user=lambda ea, key, before: bool(
                                    (lv := find_lvar(ea, key=key)) is not None and lv.has_user_name))


def _get_lvar_type(ea: int, key: str) -> str | None:
    lv = find_lvar(ea, key=key)
    return str(lv.type()) if lv is not None else None


def _set_lvar_type(ea: int, key: str, value: Any, opts: dict) -> None:
    import ida_hexrays

    from . import decomp

    lv = find_lvar(ea, key=key)
    if lv is None:
        raise IdaxError(Exit.EMPTY_SELECTION, f"no local variable {key}", "NOMATCH")
    info = ida_hexrays.lvar_saved_info_t()
    info.ll = lv
    info.type = typesupport.parse_type(value)
    if not ida_hexrays.modify_user_lvar_info(ida_funcs.get_func(ea).start_ea, ida_hexrays.MLI_TYPE, info):
        raise _fail(f"cannot set type of {lv.name!r}")
    decomp.reset()


HANDLERS["lvar_type"] = Handler(_get_lvar_type, _set_lvar_type, equal=_type_equal)


# -- bytes (patches) ---------------------------------------------------------------------------


def _get_bytes(ea: int, key: int) -> str:
    return (ida_bytes.get_bytes(ea, int(key)) or b"").hex()


def _set_bytes(ea: int, key: int, value: Any, opts: dict) -> None:
    data = bytes.fromhex(value)
    if opts.get("revert"):
        for i in range(len(data)):
            ida_bytes.revert_byte(ea + i)
        return
    ida_bytes.patch_bytes(ea, data)


HANDLERS["bytes"] = Handler(_get_bytes, _set_bytes)


# -- tags and colours -------------------------------------------------------------------------


def _get_tags(ea: int, key: Any) -> list[str]:
    from . import tags

    return tags.get(ea)


def _set_tags(ea: int, key: Any, value: Any, opts: dict) -> None:
    from . import tags

    tags.set_tags(ea, list(value or []))


HANDLERS["tags"] = Handler(_get_tags, _set_tags, equal=lambda a, b: sorted(a or []) == sorted(b or []))


def _get_color(ea: int, key: Any) -> str | None:
    c = ida_nalt.get_item_color(ea)
    if c == 0xFFFFFFFF:
        return None
    return f"{c & 0xFF:02x}{(c >> 8) & 0xFF:02x}{(c >> 16) & 0xFF:02x}"


def _set_color(ea: int, key: Any, value: Any, opts: dict) -> None:
    if not value:
        ida_nalt.del_item_color(ea)
        return
    r, g, b = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
    ida_nalt.set_item_color(ea, r | (g << 8) | (b << 16))


HANDLERS["color"] = Handler(_get_color, _set_color, equal=lambda a, b: (a or "").lower() == (b or "").lower())


# -- local types -------------------------------------------------------------------------------


def _get_local_type(ea: Any, key: str) -> str | None:
    tif = typesupport.find_local(key)
    return typesupport.type_definition(tif, key) if tif is not None else None


def _set_local_type(ea: Any, key: str, value: Any, opts: dict) -> None:
    """Define, redefine (in place, keeping the ordinal so references stay
    valid) or delete a local type."""
    til = ida_typeinf.get_idati()
    if not value:
        if typesupport.find_local(key) is not None and not ida_typeinf.del_named_type(
                til, key, ida_typeinf.NTF_TYPE):
            raise _fail(f"cannot delete local type {key!r}")
        return
    if ida_typeinf.parse_decls(til, value, None, ida_typeinf.HTI_DCL) != 0:
        raise IdaxError(Exit.USAGE, f"cannot parse definition of {key!r}", "BADDECL")


def _local_type_equal(a: Any, b: Any) -> bool:
    norm = lambda s: " ".join((s or "").replace(";", " ; ").split())  # noqa: E731
    return norm(a) == norm(b)


HANDLERS["local_type"] = Handler(_get_local_type, _set_local_type,
                                 user=lambda ea, key, before: before is not None, equal=_local_type_equal)


# -- the generic change path -----------------------------------------------------------------


def change(ctx: Ctx, kind: str, ea: int | None, key: Any, value: Any, *, force: bool = False,
           opts: dict | None = None, record: dict | None = None, journal_kind: str | None = None) -> dict:
    """Set ``kind`` at ``ea``/``key`` to ``value``; returns an edit record."""
    h = HANDLERS.get(kind)
    if h is None:
        raise IdaxError(Exit.USAGE, f"unknown edit kind {kind!r}", "USAGE")
    opts = opts or {}
    before = h.get(ea, key) if ea is not None or kind == "local_type" else None
    base = {"_t": "edit", "kind": kind, "ea": A(ea) if isinstance(ea, int) else None, "key": key,
            "before": before, "after": value}
    if record:
        base.update(record)
    if h.equal(before, value):
        base["status"] = "unchanged"
        return base
    if h.user(ea, key, before) and before not in (None, "", []) and not (force or ctx.opts.force):
        raise _fail(f"{_where(ea, key)}: {kind} was set by a user ({before!r}); use --force to overwrite")
    if ctx.opts.dry_run:
        base["status"] = "would-change"
        ctx.changes += 1
        return base
    ctx.require_writable()
    h.set(ea, key, value, opts)
    return record_change(ctx, base, kind=journal_kind or kind, ea=ea, key=key, before=before, after=value,
                         opts=opts)


def record_change(ctx: Ctx, base: dict, *, kind: str, ea: int | None, key: Any, before: Any, after: Any,
                  opts: dict | None = None) -> dict:
    """Journal a change that has been made; returns the edit record."""
    entry = journal.append({
        "kind": kind, "ea": f"{ea:#x}" if isinstance(ea, int) else None, "key": key,
        "before": before, "after": after, "author": ctx.opts.author, "command": ctx.opts.command,
        "message": ctx.opts.message or None, **({"opts": opts} if opts else {}),
        **(location(ea) if isinstance(ea, int) else {}),
    })
    base["status"] = "changed"
    base["rev"] = entry["rev"]
    ctx.changes += 1
    return base


def location(ea: int) -> dict:
    """Context that lets ``apply --rebase`` find ``ea`` in another build:
    image-base offset, and the owning function's name, body hash and offset."""
    out: dict[str, Any] = {"rva": f"{ea - ida_nalt.get_imagebase():#x}"}
    f = ida_funcs.get_func(ea)
    if f is not None:
        from .kinds.functions import body_hash

        out.update({"func": ida_funcs.get_func_name(f.start_ea), "func_hash": body_hash(f),
                    "func_off": f"{ea - f.start_ea:#x}"})
    return out


def _where(ea: Any, key: Any) -> str:
    where = f"{ea:#x}" if isinstance(ea, int) else str(key)
    return where if key in (None, "") or not isinstance(ea, int) else f"{where} [{key}]"
