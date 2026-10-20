"""Edit operations on types, functions, items and bytes."""

from __future__ import annotations

import re
from typing import Any

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_nalt
import ida_typeinf

from ...errors import Exit, IdaxError
from .. import edits, select, typesupport
from ..context import A, Ctx
from ..rpc import op
from .common import selection
from .edit import _addressable, _plain_name, finish, render

BADADDR = ida_idaapi.BADADDR


# -- type ------------------------------------------------------------------------------------


@op("type.set")
def type_set(ctx: Ctx, selectors: list[dict], decl: str, propagate: bool = False, lvar: list[dict] | None = None,
             force: bool = False) -> list[dict]:
    out: list[dict] = []
    if lvar is not None:
        funcs = list(select.functions_of(ctx, selection(ctx, lvar)))
        if len(funcs) != 1:
            raise IdaxError(Exit.USAGE, "--lvar needs exactly one function", "USAGE")
        f = funcs[0]
        for node in selectors:
            name = _plain_name(node)
            lv = edits.find_lvar(f.ea, name=name)
            if lv is None:
                raise IdaxError(Exit.EMPTY_SELECTION, f"no local variable {name!r}", "NOMATCH")
            out.append(edits.change(ctx, "lvar_type", f.ea, edits.lvar_key(lv), decl, force=force,
                                    record={"type": decl, "name": name}))
        return finish(ctx, out)
    sel = selection(ctx, selectors)
    touched: list[int] = []
    for it in _addressable(sel):
        ea = it.ea
        f = ida_funcs.get_func(ea)
        if it.kind.name == "function" and f is not None:
            ea = f.start_ea
        value = render(decl, it, ctx)
        typesupport.parse_decl(value)  # usage error before any change
        rec = edits.change(ctx, "type", ea, None, value, force=force, record={"type": value})
        out.append(rec)
        if rec["status"] == "changed":
            touched.append(ea)
    if propagate and touched:
        from .. import decomp
        from ..kinds.functions import callers

        if decomp.available():
            import ida_hexrays

            for ea in touched:
                for c in callers(ea):
                    ida_hexrays.mark_cfunc_dirty(c)
                    r = decomp.decompile(c, fresh=True)
                    out.append({"_t": "propagate", "ea": A(c), "func": ida_funcs.get_func_name(c),
                                "status": "ok" if r.ok else "failed"})
    return finish(ctx, out)


@op("type.get")
def type_get(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in sel:
        if it.kind.name == "type":
            out.append({"_t": "type", "name": it.obj["name"], "type": it.kind.get(it, "decl", ctx)})
            continue
        if not isinstance(it.ea, int):
            continue
        ea = it.ea
        f = ida_funcs.get_func(ea)
        is_func = f is not None and (it.kind.name == "function" or f.start_ea == ea)
        decl = typesupport.prototype(f.start_ea) if is_func else typesupport.type_at(ea)
        out.append({"_t": "type", "ea": A(f.start_ea if is_func else ea), "name": it.kind.get(it, "name", ctx),
                    "type": decl, "user": typesupport.is_user_type(f.start_ea if is_func else ea),
                    "guessed": is_func and typesupport.tinfo_at(f.start_ea) is None})
    return out


def _local_definitions() -> dict[str, str]:
    return {name: typesupport.type_definition(tif, name) for _, name, tif in typesupport.local_types()}


def _parse(text: str, parser: str, args: list[str]) -> int:
    til = ida_typeinf.get_idati()
    if parser == "clang":
        import ida_srclang

        ida_srclang.set_parser_argv("clang", " ".join(args))
        errors = ida_srclang.parse_decls_with_parser("clang", til, text, False)
        if errors >= 0:
            return errors
    return ida_typeinf.parse_decls(til, text, None, ida_typeinf.HTI_DCL)


@op("type.add")
def type_add(ctx: Ctx, text: str, parser: str = "clang", args: list[str] | None = None,
             replace: bool = False) -> list[dict]:
    """Parse declarations into the local types.  Identical types are left
    alone; a differing definition is a conflict (9) unless --replace."""
    ctx.require_writable()
    before = _local_definitions()
    errors = _parse(text, parser, args or [])
    after = _local_definitions()
    changed = [n for n, d in after.items() if before.get(n) != d]

    def rollback() -> None:
        for n in changed:
            edits.HANDLERS["local_type"].set(None, n, before.get(n), {})

    if errors:
        rollback()
        raise IdaxError(Exit.USAGE, f"{errors} error(s) parsing declarations", "BADDECL")
    conflicts = [n for n in changed if n in before]
    if (conflicts and not (replace or ctx.opts.force)) or ctx.opts.dry_run:
        rollback()
        if conflicts and not (replace or ctx.opts.force):
            raise IdaxError(Exit.CONFLICT, f"conflicting definition of {', '.join(conflicts)} "
                            "(use --replace)", "CONFLICT")
    out = []
    for n in changed:
        base = {"_t": "edit", "kind": "local_type", "ea": None, "key": n, "before": before.get(n),
                "after": after[n], "name": n}
        if ctx.opts.dry_run:
            base["status"] = "would-change"
            ctx.changes += 1
            out.append(base)
        else:
            out.append(edits.record_change(ctx, base, kind="local_type", ea=None, key=n, before=before.get(n),
                                           after=after[n]))
    declared = set(re.findall(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)", text)) | \
        set(re.findall(r"([A-Za-z_]\w*)\s*;\s*$", text, re.M))
    for n in sorted(declared - set(changed)):
        if n in after:
            out.append({"_t": "edit", "kind": "local_type", "ea": None, "key": n, "before": after[n],
                        "after": after[n], "name": n, "status": "unchanged"})
    if not out:
        ctx.warn("NOMATCH", "no named types declared")
    return finish(ctx, out)


@op("type.import")
def type_import(ctx: Ctx, source: str, names: list[str], definitions: dict[str, str] | None = None,
                replace: bool = False) -> list[dict]:
    """Copy named types from a type library (``source`` names a .til) or
    from definitions extracted by the client from another database."""
    defs: list[tuple[str, str]] = []
    if definitions is not None:
        defs = [(n, definitions[n]) for n in names if n in definitions]
        missing = [n for n in names if n not in definitions]
    else:
        til = ida_typeinf.load_til(source)
        if til is None:
            raise IdaxError(Exit.NOT_FOUND, f"{source}: type library not found", "NOTFOUND")
        missing = []
        for n in names:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(til, n):
                defs.append((n, typesupport.type_definition(tif, n)))
            else:
                missing.append(n)
        ida_typeinf.free_til(til)
    if missing:
        raise IdaxError(Exit.EMPTY_SELECTION, f"{source}: no type {', '.join(missing)}", "NOMATCH")
    return finish(ctx, [edits.change(ctx, "local_type", None, n, d, force=replace, record={"name": n})
                        for n, d in defs])


@op("type.definitions")
def type_definitions(ctx: Ctx, names: list[str]) -> list[dict]:
    out = []
    for n in names:
        tif = typesupport.find_local(n)
        if tif is None:
            raise IdaxError(Exit.EMPTY_SELECTION, f"no local type {n!r}", "NOMATCH")
        out.append({"_t": "type", "name": n, "decl": typesupport.type_definition(tif, n)})
    return out


@op("type.del")
def type_del(ctx: Ctx, names: list[str]) -> list[dict]:
    missing = [n for n in names if typesupport.find_local(n) is None]
    out = [edits.change(ctx, "local_type", None, n, None, force=True, record={"name": n})
           for n in names if n not in missing]
    for n in missing:
        out.append({"_t": "edit", "kind": "local_type", "key": n, "status": "unchanged", "before": None,
                    "after": None, "name": n})
    return finish(ctx, out)


@op("type.dump")
def type_dump(ctx: Ctx, names: list[str] | None = None) -> list[dict]:
    """Local types as a compilable, topologically sorted C header."""
    til = ida_typeinf.get_idati()
    ordinals: list[int] = []
    if names:
        for n in names:
            o = ida_typeinf.get_type_ordinal(til, n)
            if not o:
                raise IdaxError(Exit.EMPTY_SELECTION, f"no local type {n!r}", "NOMATCH")
            ordinals.append(o)
    else:
        ordinals = [o for o, _, _ in typesupport.local_types()]

    class P(ida_typeinf.text_sink_t):
        def __init__(self) -> None:
            super().__init__()
            self.parts: list[str] = []

        def _print(self, text: str) -> int:
            self.parts.append(text)
            return 0

    p = P()
    flags = ida_typeinf.PDF_INCL_DEPS | ida_typeinf.PDF_DEF_FWD | ida_typeinf.PDF_HEADER_CMT
    ida_typeinf.print_decls(p, til, ordinals, flags)
    text = "".join(p.parts)
    return [{"_t": "header", "types": len(ordinals), "text": text}]


@op("type.op")
def type_op(ctx: Ctx, selectors: list[dict], operand: int, as_: str, force: bool = False) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        out.append(edits.change(ctx, "operand", it.ea, int(operand), render(as_, it, ctx), force=force))
    return finish(ctx, out)


@op("type.callsite")
def type_callsite(ctx: Ctx, selectors: list[dict], decl: str, force: bool = False) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        import ida_ua

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, it.ea) or not ida_idp.is_call_insn(insn):
            raise IdaxError(Exit.USAGE, f"{it.ea:#x} is not a call instruction", "USAGE")
        out.append(edits.change(ctx, "callsite", it.ea, None, render(decl, it, ctx), force=force,
                                record={"type": decl}))
    return finish(ctx, out)


# -- func --------------------------------------------------------------------------------------


@op("func.create")
def func_create(ctx: Ctx, selectors: list[dict], end: int | None = None) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        value = {"start": f"{it.ea:#x}", "end": f"{end:#x}" if end is not None else None}
        out.append(edits.change(ctx, "func", it.ea, None, value, force=True))
    return finish(ctx, out)


@op("func.delete")
def func_delete(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for fi in select.functions_of(ctx, sel):
        out.append(edits.change(ctx, "func", fi.ea, None, None, force=True,
                                record={"name": ida_funcs.get_func_name(fi.ea)}))
    return finish(ctx, out)


@op("func.set")
def func_set(ctx: Ctx, selectors: list[dict], start: int | None = None, end: int | None = None,
             flags: list[str] | None = None, frame: int | None = None) -> list[dict]:
    from ..kinds.functions import FLAG_BITS

    sel = selection(ctx, selectors)
    out = []
    for fi in select.functions_of(ctx, sel):
        ea = fi.ea
        if end is not None:
            out.append(edits.change(ctx, "func", ea, None, {"start": f"{ea:#x}", "end": f"{end:#x}"}, force=True))
        if flags:
            current = set(edits.HANDLERS["func_flags"].get(ea, None) or [])
            for fl in flags:
                sign, name = (fl[0], fl[1:]) if fl[0] in "+-" else ("+", fl)
                name = name.lower()
                if name not in FLAG_BITS:
                    raise IdaxError(Exit.USAGE, f"--flags: unknown flag {name!r} (one of "
                                    f"{', '.join(sorted(FLAG_BITS))})", "USAGE")
                if sign == "+":
                    current.add(name)
                else:
                    current.discard(name)
            out.append(edits.change(ctx, "func_flags", ea, None, sorted(current), force=True))
        if frame is not None:
            out.append(edits.change(ctx, "func_frame", ea, None, int(frame), force=True))
        if start is not None:
            out.append(edits.change(ctx, "func_start", ea, None, f"{start:#x}", force=True))
    return finish(ctx, out)


@op("func.tail")
def func_tail(ctx: Ctx, selectors: list[dict], add: list[int] | None = None, remove: int | None = None) -> list:
    sel = selection(ctx, selectors)
    funcs = list(select.functions_of(ctx, sel))
    if len(funcs) != 1:
        raise IdaxError(Exit.USAGE, "func tail needs exactly one function", "USAGE")
    ea = funcs[0].ea
    out = []
    if add:
        out.append(edits.change(ctx, "func_tail", ea, f"{add[0]:#x}", f"{add[1]:#x}", force=True))
    if remove is not None:
        out.append(edits.change(ctx, "func_tail", ea, f"{remove:#x}", None, force=True))
    return finish(ctx, out)


def _get_frame(ea: int, key: Any) -> int | None:
    f = ida_funcs.get_func(ea)
    return int(f.frsize) if f is not None else None


def _set_frame(ea: int, key: Any, value: Any, opts: dict) -> None:
    import ida_frame

    f = ida_funcs.get_func(ea)
    if not ida_frame.set_frame_size(f, int(value), f.frregs, f.argsize):
        raise IdaxError(Exit.CONFLICT, f"cannot set frame size of {ea:#x}", "CONFLICT")


edits.HANDLERS["func_frame"] = edits.Handler(_get_frame, _set_frame)


# -- make ----------------------------------------------------------------------------------------

_ENCODINGS = {"utf-8": "STRTYPE_C", "utf8": "STRTYPE_C", "ascii": "STRTYPE_C", "c": "STRTYPE_C",
              "utf-16le": "STRTYPE_C_16", "utf-16": "STRTYPE_C_16", "utf16": "STRTYPE_C_16",
              "utf-32le": "STRTYPE_C_32", "utf-32": "STRTYPE_C_32", "pascal": "STRTYPE_PASCAL"}


@op("make")
def make(ctx: Ctx, kind: str, selectors: list[dict], count: int | None = None, type: str | None = None,
         base: int | None = None, encoding: str | None = None, size: int | None = None,
         jumptable: str | None = None, force: bool = False) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        ea = it.ea
        if jumptable:
            out.append(_jumptable(ctx, ea, jumptable))
            continue
        value: dict[str, Any]
        if kind in ("code", "unknown", "byte", "word", "dword", "qword", "oword", "tbyte", "float", "double"):
            value = {"kind": kind}
        elif kind == "string":
            strtype = getattr(ida_nalt, _ENCODINGS.get((encoding or "utf-8").lower(), ""), None)
            if strtype is None:
                raise IdaxError(Exit.USAGE, f"--encoding {encoding}: one of {', '.join(_ENCODINGS)}", "USAGE")
            value = {"kind": "string", "strtype": strtype, "size": size or 0}
        elif kind == "array":
            if not count or count < 1:
                raise IdaxError(Exit.USAGE, "make array needs --count N (N >= 1)", "USAGE")
            current = edits.HANDLERS["item"].get(ea, None)
            elem = current.get("of") or (current["kind"] if current["kind"] in (
                "byte", "word", "dword", "qword", "float", "double") else "byte")
            value = {"kind": "array", "of": type or elem, "count": count}
        elif kind == "struct":
            if not type:
                raise IdaxError(Exit.USAGE, "make struct needs --type NAME", "USAGE")
            value = {"kind": "struct", "type": type}
        elif kind == "offset":
            ptr = "qword" if ida_ida.inf_is_64bit() else "dword"
            value = {"kind": ptr, "offset": True, "base": base or 0}
        elif kind == "align":
            value = {"kind": "align", "size": size or 0}
        else:
            raise IdaxError(Exit.USAGE, f"unknown item kind {kind!r}", "USAGE")
        out.append(edits.change(ctx, "item", ea, None, value, force=True))
    return finish(ctx, out)


def _jumptable(ctx: Ctx, ea: int, spec: str) -> dict:
    """``--jumptable table=ADDR,count=N[,elsize=4][,base=ADDR][,default=ADDR][,lowcase=N]``"""
    from ...lang.values import parse_int

    fields: dict[str, int] = {}
    for part in spec.split(","):
        k, eq, v = part.partition("=")
        if not eq or k not in ("table", "count", "elsize", "base", "default", "lowcase"):
            raise IdaxError(Exit.USAGE, f"--jumptable: bad item {part!r}", "USAGE")
        fields[k] = parse_int(v)
    if "table" not in fields or "count" not in fields:
        raise IdaxError(Exit.USAGE, "--jumptable needs table= and count=", "USAGE")
    ctx.require_writable()
    si = ida_nalt.switch_info_t()
    si.jumps = fields["table"]
    si.ncases = fields["count"]
    elsize = fields.get("elsize", 8 if ida_ida.inf_is_64bit() else 4)
    si.set_jtable_element_size(elsize)
    if "base" in fields:
        si.set_elbase(fields["base"])
    if "default" in fields:
        si.defjump = fields["default"]
    si.lowcase = fields.get("lowcase", 0)
    si.startea = ea
    ida_nalt.set_switch_info(ea, si)
    ida_bytes.create_data(si.jumps, {1: ida_bytes.FF_BYTE, 2: ida_bytes.FF_WORD, 4: ida_bytes.FF_DWORD,
                                    8: ida_bytes.FF_QWORD}[elsize], elsize * si.ncases, BADADDR)
    import ida_xref

    ida_xref.create_switch_xrefs(ea, si)
    from .. import journal

    rev = journal.append({"kind": "switch", "ea": f"{ea:#x}", "key": None, "before": None, "after": spec,
                          "author": ctx.opts.author, "command": ctx.opts.command})
    ctx.changes += 1
    return {"_t": "edit", "kind": "switch", "ea": A(ea), "after": spec, "status": "changed", "rev": rev["rev"]}


# -- patch ----------------------------------------------------------------------------------------

NOPS = {"metapc": "90", "arm": None, "mips": "00000000", "mipsl": "00000000", "mipsb": "00000000",
        "ppc": "60000000", "ppcl": "00000060", "riscv": "13000000"}


def _nop_bytes(ea: int, length: int) -> bytes:
    proc = ida_ida.inf_get_procname().lower()
    if proc == "metapc":
        return b"\x90" * length
    if proc == "arm":
        if ida_ida.inf_is_64bit():
            unit = bytes.fromhex("1f2003d5")
        else:
            import ida_segregs

            thumb = ida_segregs.get_sreg(ea, ida_idp.str2reg("T")) == 1
            unit = bytes.fromhex("00bf") if thumb else bytes.fromhex("00f020e3")
    elif proc in NOPS and NOPS[proc]:
        unit = bytes.fromhex(NOPS[proc])
        if ida_ida.inf_is_be() and proc.startswith("ppc"):
            unit = bytes.fromhex("60000000")
    else:
        ok, unit = _assemble(ea, "nop")
        if not ok:
            raise IdaxError(Exit.USAGE, f"no NOP encoding known for processor {proc}", "USAGE")
    if length % len(unit):
        raise IdaxError(Exit.USAGE, f"{ea:#x}: item length {length} is not a multiple of the NOP size", "USAGE")
    return unit * (length // len(unit))


def _assemble(ea: int, line: str) -> tuple[bool, bytes]:
    import idautils

    res = idautils.Assemble(ea, line)
    if isinstance(res, tuple):
        ok, data = res
        return bool(ok), data if isinstance(data, bytes) else b""
    return False, b""


@op("patch.bytes")
def patch_bytes(ctx: Ctx, selectors: list[dict], hexdata: str) -> list[dict]:
    data = bytes.fromhex(hexdata)
    sel = selection(ctx, selectors)
    out = [edits.change(ctx, "bytes", it.ea, len(data), data.hex(), force=True)
           for it in _addressable(sel)]
    return finish(ctx, out)


@op("patch.asm")
def patch_asm(ctx: Ctx, selectors: list[dict], lines: list[str]) -> list[dict]:
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        ea = it.ea
        for line in lines:
            ok, data = _assemble(ea, line)
            if not ok or not data:
                raise IdaxError(Exit.USAGE, f"{ea:#x}: cannot assemble {line!r} (processor "
                                f"{ida_ida.inf_get_procname()} may have no assembler)", "USAGE")
            out.append(edits.change(ctx, "bytes", ea, len(data), data.hex(), force=True, record={"asm": line}))
            import ida_ua

            ida_ua.create_insn(ea)
            ea += len(data)
    return finish(ctx, out)


@op("patch.nop")
def patch_nop(ctx: Ctx, selectors: list[dict]) -> list[dict]:
    from .common import spans

    sel = selection(ctx, selectors)
    out = []
    for s, e in spans(sel):
        from ..kinds.base import iter_heads

        for ea in iter_heads(s, e):
            length = ida_bytes.get_item_size(ea)
            out.append(edits.change(ctx, "bytes", ea, length, _nop_bytes(ea, length).hex(), force=True))
    return finish(ctx, out)


@op("patch.revert")
def patch_revert(ctx: Ctx, selectors: list[dict] | None = None) -> list[dict]:
    from ..kinds import KINDS
    from .common import spans, within

    pk = KINDS["patch"]
    patches = list(pk.all(ctx))
    if selectors:
        sp = spans(select.evaluate(ctx, selectors))
        patches = [p for p in patches if within(p.ea, sp)]
    out = []
    for p in patches:
        original = p.obj["original"].hex()
        out.append(edits.change(ctx, "bytes", p.ea, len(p.obj["original"]), original, force=True,
                                opts={"revert": True}))
    if not patches:
        ctx.warn("NOMATCH", "no patched bytes in the selection")
    return finish(ctx, out)

