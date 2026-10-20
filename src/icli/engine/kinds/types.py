"""Local types, type libraries and FLIRT signatures."""

from __future__ import annotations

from typing import Iterable

import ida_funcs
import ida_typeinf

from .. import typesupport
from ..context import Ctx
from .base import Item, Kind, register


@register
class Types(Kind):
    name = "type"
    plural = "types"
    record = "type"
    defaults = ["ordinal", "name", "kind", "size"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for ordinal, name, tif in typesupport.local_types():
            yield Item(self, None, {"ordinal": ordinal, "name": name, "tif": tif}, key=("type", name))

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        return [it.obj["name"]]

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj["name"]

    def f_ordinal(self, it: Item, ctx: Ctx) -> int:
        return it.obj["ordinal"]

    def f_kind(self, it: Item, ctx: Ctx) -> str:
        return typesupport.type_kind(it.obj["tif"])

    def f_size(self, it: Item, ctx: Ctx) -> int | None:
        s = it.obj["tif"].get_size()
        return None if s == ida_typeinf.BADSIZE else int(s)

    def f_decl(self, it: Item, ctx: Ctx) -> str:
        return typesupport.type_definition(it.obj["tif"], it.obj["name"])

    def f_type(self, it: Item, ctx: Ctx) -> str:
        return self.get(it, "decl", ctx)

    def f_members(self, it: Item, ctx: Ctx) -> int | None:
        tif = it.obj["tif"]
        if tif.is_udt():
            return int(tif.get_udt_nmembers())
        if tif.is_enum():
            return int(tif.get_enum_nmembers())
        return None

    def f_comment(self, it: Item, ctx: Ctx) -> str | None:
        return it.obj["tif"].get_type_cmt() or None

    def f_ea(self, it: Item, ctx: Ctx) -> None:
        return None

    def f_segment(self, it: Item, ctx: Ctx) -> None:
        return None


@register
class Tils(Kind):
    name = "til"
    plural = "tils"
    record = "til"
    defaults = ["name", "desc", "kind"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        til = ida_typeinf.get_idati()
        yield Item(self, None, {"name": "(local)", "desc": til.desc or "", "kind": "local",
                                "ntypes": len(typesupport.local_types())}, key=("til", "(local)"))
        for i in range(til.nbases):
            base = til.base(i)
            yield Item(self, None, {"name": base.name, "desc": base.desc or "", "kind": "loaded"},
                       key=("til", base.name))

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        return [it.obj["name"]]

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj["name"]

    def f_desc(self, it: Item, ctx: Ctx) -> str:
        return it.obj["desc"]

    def f_kind(self, it: Item, ctx: Ctx) -> str:
        return it.obj["kind"]

    def f_ntypes(self, it: Item, ctx: Ctx) -> int | None:
        return it.obj.get("ntypes")

    def f_ea(self, it: Item, ctx: Ctx) -> None:
        return None


def applied_signatures() -> list[dict]:
    out = []
    for i in range(ida_funcs.get_idasgn_qty()):
        name, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(i) if hasattr(
            ida_funcs, "get_idasgn_desc_with_matches") else (*ida_funcs.get_idasgn_desc(i), -1)
        title = ida_funcs.get_idasgn_title(name) if hasattr(ida_funcs, "get_idasgn_title") else ""
        out.append({"name": name, "title": title or "", "matches": int(nmatches), "optlibs": optlibs or ""})
    return out


@register
class Sigs(Kind):
    name = "sig"
    plural = "sigs"
    record = "sig"
    defaults = ["name", "title", "matches"]

    def all(self, ctx: Ctx) -> Iterable[Item]:
        for s in applied_signatures():
            yield Item(self, None, s, key=("sig", s["name"]))

    def names(self, it: Item, ctx: Ctx) -> list[str]:
        return [it.obj["name"]]

    def f_name(self, it: Item, ctx: Ctx) -> str:
        return it.obj["name"]

    def f_title(self, it: Item, ctx: Ctx) -> str:
        return it.obj["title"]

    def f_matches(self, it: Item, ctx: Ctx) -> int:
        return it.obj["matches"]

    def f_ea(self, it: Item, ctx: Ctx) -> None:
        return None
