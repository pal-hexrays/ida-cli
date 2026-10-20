"""Comments, bookmarks, tags, problems, fixups and patched bytes."""

from __future__ import annotations

from typing import Iterable

import ida_bytes
import ida_fixup
import ida_funcs
import ida_idaapi
import ida_lines
import ida_problems
import ida_segment

from .. import tags as tagstore
from ..context import A, Ctx
from .base import Item, Kind, register

BADADDR = ida_idaapi.BADADDR

COMMENT_KINDS = ("regular", "repeatable", "anterior", "posterior", "function", "function_repeatable")


def _extra(ea: int, base: int) -> str | None:
    lines = []
    i = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, base + i)
        if line is None:
            break
        lines.append(line)
        i += 1
    return "\n".join(lines) if lines else None


def comments_at(ea: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for kind, value in (("regular", ida_bytes.get_cmt(ea, False)), ("repeatable", ida_bytes.get_cmt(ea, True)),
                        ("anterior", _extra(ea, ida_lines.E_PREV)),
                        ("posterior", _extra(ea, ida_lines.E_NEXT))):
        if value:
            out[kind] = value
    f = ida_funcs.get_func(ea)
    if f is not None and f.start_ea == ea:
        for kind, rep in (("function", False), ("function_repeatable", True)):
            v = ida_funcs.get_func_cmt(f, rep)
            if v:
                out[kind] = v
    return out


@register
class Comments(Kind):
    name = "comment"
    plural = "comments"
    record = "comment"
    defaults = ["ea", "kind", "text"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            ea = s.start_ea
            while ea != BADADDR and ea < s.end_ea:
                fl = ida_bytes.get_flags(ea)
                if ida_bytes.has_cmt(fl) or ida_bytes.has_extra_cmts(fl) or (
                        (f := ida_funcs.get_func(ea)) is not None and f.start_ea == ea):
                    for kind, text in comments_at(ea).items():
                        yield Item(self, ea, {"kind": kind, "text": text}, key=("comment", ea, kind))
                ea = ida_bytes.next_head(ea, s.end_ea)

    def at(self, ctx: Ctx, ea: int) -> Item | None:
        for kind, text in comments_at(ea).items():
            return Item(self, ea, {"kind": kind, "text": text}, key=("comment", ea, kind))
        return None

    def f_kind(self, it: Item, ctx: Ctx) -> str:
        return it.obj["kind"]

    def f_text(self, it: Item, ctx: Ctx) -> str:
        return it.obj["text"]

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        return [it.obj["text"]]


@register
class Tags(Kind):
    name = "tag"
    plural = "tags"
    record = "tag"
    defaults = ["ea", "tag", "name"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for ea, tags in sorted(tagstore.all_tags().items()):
            for t in tags:
                yield Item(self, ea, {"tag": t}, key=("tag", ea, t))

    def f_tag(self, it: Item, ctx: Ctx) -> str:
        return it.obj["tag"]

    def f_color(self, it: Item, ctx: Ctx) -> str | None:
        import ida_nalt

        c = ida_nalt.get_item_color(it.ea)
        if c == 0xFFFFFFFF:
            return None
        # IDA stores BGR
        return f"{c & 0xFF:02x}{(c >> 8) & 0xFF:02x}{(c >> 16) & 0xFF:02x}"


@register
class Bookmarks(Kind):
    name = "bookmark"
    plural = "bookmarks"
    record = "bookmark"
    defaults = ["ea", "text", "source"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        seen: set[int] = set()
        for ea, tags in sorted(tagstore.all_tags().items()):
            for t in tags:
                if t.startswith("bookmark:") or t == "bookmark":
                    seen.add(ea)
                    yield Item(self, ea, {"text": t.partition(":")[2], "source": "tag"},
                               key=("bookmark", ea, t))
        for ea, text in _ida_bookmarks():
            if ea not in seen:
                yield Item(self, ea, {"text": text, "source": "ida"}, key=("bookmark", ea, text))

    def f_text(self, it: Item, ctx: Ctx) -> str:
        return it.obj["text"]

    def f_source(self, it: Item, ctx: Ctx) -> str:
        return it.obj["source"]


def _ida_bookmarks() -> list[tuple[int, str]]:
    """Marked positions of the disassembly view (idc.get_bookmark)."""
    import idc

    out = []
    for slot in range(1, 1025):
        ea = idc.get_bookmark(slot)
        if ea is None or ea == BADADDR:
            continue
        out.append((ea, idc.get_bookmark_desc(slot) or ""))
    return out


_PROBLEMS = {
    getattr(ida_problems, n): n[3:].lower()
    for n in dir(ida_problems)
    if n.startswith("PR_") and isinstance(getattr(ida_problems, n), int) and n != "PR_END"
}


@register
class Problems(Kind):
    name = "problem"
    plural = "problems"
    record = "problem"
    defaults = ["ea", "type", "desc"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for ptype, pname in sorted(_PROBLEMS.items()):
            ea = ida_problems.get_problem(ptype, 0)
            while ea != BADADDR:
                yield Item(self, ea, {"type": pname, "code": ptype}, key=("problem", ea, ptype))
                ea = ida_problems.get_problem(ptype, ea + 1)

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return it.obj["type"]

    def f_desc(self, it: Item, ctx: Ctx) -> str:
        return ida_problems.get_problem_desc(it.obj["code"], it.ea) or ida_problems.get_problem_name(
            it.obj["code"])


@register
class Fixups(Kind):
    name = "fixup"
    plural = "fixups"
    record = "fixup"
    defaults = ["ea", "type", "target", "size"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        ea = ida_fixup.get_first_fixup_ea()
        while ea != BADADDR:
            fd = ida_fixup.fixup_data_t()
            if fd.get(ea):
                yield Item(self, ea, fd, key=("fixup", ea))
            ea = ida_fixup.get_next_fixup_ea(ea)

    def f_type(self, it: Item, ctx: Ctx) -> str:
        t = it.obj.get_type()
        try:
            return ida_lines.tag_remove(ida_fixup.get_fixup_desc(it.ea, it.obj) or "") or str(t)
        except Exception:
            return str(t)

    def f_target(self, it: Item, ctx: Ctx) -> object:
        try:
            return A(it.obj.off + (ida_segment.getseg(it.ea).start_ea if it.obj.sel == BADADDR else 0))
        except Exception:
            return None

    def f_size(self, it: Item, ctx: Ctx) -> int:
        return int(ida_fixup.calc_fixup_size(it.obj.get_type()))


@register
class Patches(Kind):
    name = "patch"
    plural = "patches"
    record = "patch"
    defaults = ["ea", "size", "original", "patched", "func"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        """Runs of contiguous patched bytes."""
        runs: list[list[int]] = []

        def visit(ea: int, fpos: int, org: int, val: int) -> int:
            if runs and runs[-1][0] + len(runs[-1][1]) == ea:
                runs[-1][1].append(org)
                runs[-1][2].append(val)
            else:
                runs.append([ea, [org], [val]])  # type: ignore[list-item]
            return 0

        ida_bytes.visit_patched_bytes(0, BADADDR, visit)
        for ea, org, val in runs:
            yield Item(self, ea, {"original": bytes(org), "patched": bytes(val)},
                       end=ea + len(org), key=("patch", ea))

    def f_original(self, it: Item, ctx: Ctx) -> str:
        return it.obj["original"].hex()

    def f_patched(self, it: Item, ctx: Ctx) -> str:
        return it.obj["patched"].hex()

