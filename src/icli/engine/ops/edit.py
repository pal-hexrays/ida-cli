"""Edit operations: rename, comment, tag (type/func/make/patch in edit_code)."""

from __future__ import annotations

import re
from typing import Any

import ida_funcs
import ida_idaapi
import ida_name

from ...errors import Exit, IcliError
from ...lang import template as tmpl
from .. import edits, edits_code  # noqa: F401  (edits_code registers handlers)
from ..context import Ctx
from ..kinds import Item
from ..rpc import op
from .common import selection

BADADDR = ida_idaapi.BADADDR


def render(text: str, it: Item, ctx: Ctx) -> str:
    """Expand ``{field}`` placeholders of an edit argument for one item."""
    if "{" not in text:
        return text
    return tmpl.render_inline(text, lambda f: it.kind.get(it, f, ctx))


def finish(ctx: Ctx, out: list[dict]) -> list[dict]:
    if ctx.opts.dry_run and not ctx.changes:
        ctx.set_status(Exit.NEGATIVE)
    return out


def _addressable(sel: Any) -> list[Item]:
    items = [it for it in sel if isinstance(it.ea, int)]
    if not items:
        raise IcliError(Exit.EMPTY_SELECTION, "selection contains no address", "NOMATCH")
    return items


def unique_name(base: str, ea: int) -> str:
    """``base``, or ``base_1``, ``base_2``... when used at another address."""
    name, i = base, 1
    while ida_name.get_name_ea(BADADDR, name) not in (BADADDR, ea):
        name = f"{base}_{i}"
        i += 1
    return name


@op("rename")
def rename(ctx: Ctx, selectors: list[dict] | None = None, name: str | None = None, local: bool = False,
           public: bool = False, weak: bool = False, regex: str | None = None, lvar: list[dict] | None = None,
           unique: bool = False, clear: bool = False, force: bool = False,
           mapping: list[dict] | None = None) -> list[dict]:
    opts = {k: True for k, v in (("local", local), ("public", public), ("weak", weak)) if v}
    out: list[dict] = []
    if mapping is not None:
        for row in mapping:
            sel = selection(ctx, [row["selector"]])
            for it in _addressable(sel):
                out.append(_rename_one(ctx, it, render(row["name"], it, ctx), opts, unique, force))
        return finish(ctx, out)
    if lvar is not None:
        return finish(ctx, _rename_lvars(ctx, lvar, selectors or [], name, force))
    sel = selection(ctx, selectors)
    if regex:
        pattern, repl, flags = _parse_sub(regex)
        for it in _addressable(sel):
            current = ida_name.get_name(it.ea) or ""
            new = pattern.sub(repl, current, count=0 if "g" in flags else 1)
            if new != current:
                out.append(_rename_one(ctx, it, new, opts, unique, force))
            else:
                out.append({"_t": "edit", "kind": "name", "ea": it.kind.get(it, "ea", ctx), "before": current,
                            "after": current, "status": "unchanged", "name": current})
        return finish(ctx, out)
    for it in _addressable(sel):
        new = "" if clear else render(name or "", it, ctx)
        if not clear and not new:
            raise IcliError(Exit.USAGE, "empty name (use --clear to restore the dummy name)", "USAGE")
        out.append(_rename_one(ctx, it, new or None, opts, unique, force))
    return finish(ctx, out)


def _rename_one(ctx: Ctx, it: Item, new: str | None, opts: dict, unique: bool, force: bool) -> dict:
    if new and unique:
        new = unique_name(new, it.ea)
    rec = edits.change(ctx, "name", it.ea, None, new, force=force, opts=opts,
                       record={"name": new})
    if new is None and rec["status"] != "unchanged":
        rec["name"] = ida_name.get_name(it.ea) or None
    return rec


def _parse_sub(expr: str) -> tuple["re.Pattern[str]", str, str]:
    if len(expr) < 4 or expr[0] != "s":
        raise IcliError(Exit.USAGE, f"--regex expects s/re/repl/[flags], not {expr!r}", "USAGE")
    delim = expr[1]
    parts = re.split(rf"(?<!\\){re.escape(delim)}", expr[2:])
    if len(parts) != 3:
        raise IcliError(Exit.USAGE, f"--regex expects s/re/repl/[flags], not {expr!r}", "USAGE")
    pat, repl, flags = parts
    try:
        rx = re.compile(pat, re.I if "i" in flags else 0)
    except re.error as error:
        raise IcliError(Exit.USAGE, f"--regex: {error}", "USAGE")
    repl = re.sub(r"\$(\d)", r"\\\1", repl)
    return rx, repl, flags


def _rename_lvars(ctx: Ctx, func_sel: list[dict], names: list[dict], new: str | None, force: bool) -> list[dict]:
    """``rename --lvar FUNC target OLD NEW``: ``names`` are selector ASTs whose
    text is the old variable name."""
    from .. import select

    funcs = list(select.functions_of(ctx, selection(ctx, func_sel)))
    if len(funcs) != 1:
        raise IcliError(Exit.USAGE, "--lvar needs exactly one function", "USAGE")
    f = funcs[0]
    out = []
    for node in names:
        old = _plain_name(node)
        lv = edits.find_lvar(f.ea, name=old)
        if lv is None:
            if new and edits.find_lvar(f.ea, name=new) is not None:
                out.append({"_t": "edit", "kind": "lvar_name", "ea": f.kind.get(f, "ea", ctx), "key": None,
                            "before": new, "after": new, "status": "unchanged", "name": new, "func":
                            ida_funcs.get_func_name(f.ea)})
                continue
            raise IcliError(Exit.EMPTY_SELECTION, f"{ida_funcs.get_func_name(f.ea)}: no local variable {old!r}",
                            "NOMATCH")
        key = edits.lvar_key(lv)
        rec = edits.change(ctx, "lvar_name", f.ea, key, new, force=force,
                           record={"name": new, "func": ida_funcs.get_func_name(f.ea)})
        out.append(rec)
    return out


def _plain_name(node: dict) -> str:
    if node.get("op") == "addr" and len(node["expr"]["terms"]) == 1 and "name" in node["expr"]["terms"][0][1]:
        return node["expr"]["terms"][0][1]["name"]
    raise IcliError(Exit.USAGE, "--lvar: give the local variable's current name", "USAGE")


@op("comment")
def comment(ctx: Ctx, selectors: list[dict], text: str, kind: str = "regular", append: bool = False,
            force: bool = False) -> list[dict]:
    if kind not in edits.COMMENT_KINDS:
        raise IcliError(Exit.USAGE, f"--kind {kind}: one of {', '.join(edits.COMMENT_KINDS)}", "USAGE")
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        ea = it.ea
        if kind == "function":
            f = ida_funcs.get_func(ea)
            if f is None:
                raise IcliError(Exit.EMPTY_SELECTION, f"no function contains {ea:#x}", "NOMATCH")
            ea = f.start_ea
        value = render(text, it, ctx)
        if append and value:
            current = edits.HANDLERS["comment"].get(ea, kind) or ""
            if current and value not in current.split("\n"):
                value = current + "\n" + value
            elif current:
                value = current
        rec = edits.change(ctx, "comment", ea, kind, value or None, force=force, record={"comment": value or None})
        out.append(rec)
    return finish(ctx, out)


@op("tag")
def tag(ctx: Ctx, selectors: list[dict], tags: list[str], remove: bool = False, color: str | None = None,
        force: bool = False) -> list[dict]:
    if color is not None and not re.fullmatch(r"[0-9a-fA-F]{6}", color):
        raise IcliError(Exit.USAGE, f"--color {color}: expected rrggbb", "USAGE")
    sel = selection(ctx, selectors)
    out = []
    for it in _addressable(sel):
        current = edits.HANDLERS["tags"].get(it.ea, None)
        rendered = [render(t, it, ctx) for t in tags]
        if remove:
            new = [t for t in current if t not in rendered]
        else:
            new = sorted(dict.fromkeys([*current, *rendered]))
        rec = edits.change(ctx, "tags", it.ea, None, new, force=True, record={"tags": new})
        out.append(rec)
        if color is not None or (remove and not new):
            want = None if remove else color
            out.append(edits.change(ctx, "color", it.ea, None, want, force=True, record={"color": want}))
    return finish(ctx, out)
