"""log, undo and apply over the edit journal."""

from __future__ import annotations

import calendar
import re
import time
from typing import Any

import ida_funcs
import ida_idaapi
import ida_nalt
import ida_name

from ...errors import Exit, IdaxError
from ...lang.values import parse_address_number, parse_duration
from .. import edits, journal
from ..context import Ctx
from ..rpc import op
from .edit import finish

# Record fields that map query records onto edit kinds for ``apply``.
FIELD_KINDS = [("name", "name", None), ("type", "type", None), ("comment", "comment", "regular"),
               ("rcomment", "comment", "repeatable"), ("tags", "tags", None)]


def _since_filter(since: str | None) -> Any:
    if not since:
        return lambda rec: True
    if re.fullmatch(r"\d+", since):
        rev = int(since)
        return lambda rec: rec.get("rev", 0) > rev
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", since):
        stamp = since if "T" in since else since + "T00:00:00Z"
        return lambda rec: rec.get("time", "") >= stamp
    cutoff = time.time() - parse_duration(since)
    return lambda rec: calendar.timegm(time.strptime(rec.get("time", "1970-01-01T00:00:00Z"),
                                                     "%Y-%m-%dT%H:%M:%SZ")) >= cutoff


@op("log")
def log(ctx: Ctx, since: str | None = None, author: str | None = None, kind: str | None = None,
        selectors: list[dict] | None = None) -> list[dict]:
    keep = _since_filter(since)
    kinds = set(kind.split(",")) if kind else None
    sp = None
    if selectors:
        from .. import select
        from .common import spans

        sp = spans(select.evaluate(ctx, selectors))
    out = []
    for rec in journal.records():
        if not keep(rec) or (author and rec.get("author") != author) or (kinds and rec.get("kind") not in kinds):
            continue
        if sp is not None:
            ea = parse_address_number(rec.get("ea") or "") if rec.get("ea") else None
            if ea is None or not any(s <= ea < e for s, e in sp):
                continue
        out.append({"_t": "journal", **rec})
    return out


def _ea(rec: dict) -> int | None:
    v = rec.get("ea")
    if v is None or isinstance(v, int):
        return v
    return parse_address_number(str(v))


def _invert(ctx: Ctx, rec: dict) -> list[dict]:
    kind = rec["kind"]
    if kind == "exec":
        out = []
        for sub in reversed(rec.get("changes", [])):
            out.extend(_invert(ctx, sub))
        return out
    if kind == "switch":
        ea = _ea(rec)
        ctx.require_writable()
        ida_nalt.del_switch_info(ea)
        entry = journal.append({"kind": "switch", "ea": rec["ea"], "before": rec.get("after"), "after": None,
                                "undo_of": rec.get("rev"), "author": ctx.opts.author,
                                "command": ctx.opts.command})
        ctx.changes += 1
        return [{"_t": "edit", "kind": "switch", "ea": rec["ea"], "status": "changed", "rev": entry["rev"]}]
    opts = dict(rec.get("opts") or {})
    if kind == "bytes":
        opts.pop("revert", None)
    r = edits.change(ctx, kind, _ea(rec), rec.get("key"), rec.get("before"), force=True, opts=opts,
                     record={"undo_of": rec.get("rev")})
    return [r]


@op("undo")
def undo(ctx: Ctx, to: int | None = None, n: int = 1) -> list[dict]:
    entries = list(journal.records())
    if to is not None:
        if to < 0 or to > len(entries):
            raise IdaxError(Exit.USAGE, f"--to {to}: journal has revisions 1..{len(entries)}", "USAGE")
        targets = [e for e in entries if e["rev"] > to]
    else:
        if n < 1:
            raise IdaxError(Exit.USAGE, "-n must be >= 1", "USAGE")
        targets = entries[-n:]
    if not targets:
        ctx.warn("NOMATCH", "nothing to undo")
        return []
    out = []
    for rec in reversed(targets):
        out.extend(_invert(ctx, rec))
    return finish(ctx, out)


def rebase_ea(rec: dict) -> int | None:
    """Translate a record's address into this database: by function body
    hash or name plus offset, else by image-base offset."""
    from ..kinds.functions import body_hash

    ea = _ea(rec)
    h, name, off = rec.get("func_hash"), rec.get("func"), rec.get("func_off")
    if off is not None and (h or name):
        offset = parse_address_number(off) if isinstance(off, str) else int(off)
        candidates = []
        if name:
            fea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
            f = ida_funcs.get_func(fea) if fea != ida_idaapi.BADADDR else None
            if f is not None and f.start_ea == fea and (not h or body_hash(f) == h):
                return f.start_ea + offset
            if f is not None:
                candidates.append(f)
        if h:
            for i in range(ida_funcs.get_func_qty()):
                f = ida_funcs.getn_func(i)
                if body_hash(f) == h:
                    return f.start_ea + offset
        if candidates:
            return candidates[0].start_ea + offset
    if rec.get("rva") is not None:
        rva = parse_address_number(rec["rva"]) if isinstance(rec["rva"], str) else int(rec["rva"])
        return ida_nalt.get_imagebase() + rva
    return ea


def _changes_of(rec: dict) -> list[tuple[str, Any, Any]]:
    """(kind, key, value) pairs a record asks for."""
    if rec.get("_t") in (None, "journal", "edit") and rec.get("kind") in edits.HANDLERS:
        if "after" in rec:
            return [(rec["kind"], rec.get("key"), rec["after"])]
    if rec.get("kind") == "exec" and rec.get("changes"):
        out = []
        for sub in rec["changes"]:
            out.extend(_changes_of(sub))
        return out
    out = []
    for field, kind, key in FIELD_KINDS:
        if field in rec and rec[field] is not None and not (field == "type" and rec.get("_t") == "type"
                                                            and "ea" not in rec):
            out.append((kind, key, rec[field]))
    return out


@op("apply")
def apply(ctx: Ctx, records: list[dict], on_conflict: str = "fail", only: list[str] | None = None,
          rebase: bool = False) -> list[dict]:
    if on_conflict not in ("fail", "skip", "ours", "theirs"):
        raise IdaxError(Exit.USAGE, "--on-conflict: one of fail, skip, ours, theirs", "USAGE")
    only_kinds = set()
    for k in only or []:
        only_kinds |= {"name", "lvar_name"} if k == "rename" else {"type", "lvar_type"} if k == "type" else {k}
    out: list[dict] = []
    skipped = 0
    for rec in records:
        if rec.get("_t") == "diag":
            continue
        ea = rebase_ea(rec) if rebase else _ea(rec)
        for kind, key, value in _changes_of(rec):
            if only_kinds and kind not in only_kinds:
                continue
            if kind != "local_type" and ea is None:
                skipped += 1
                ctx.warn("SKIPPED", f"record without an address: {rec}")
                continue
            h = edits.HANDLERS[kind]
            current = h.get(ea, key) if ea is not None or kind == "local_type" else None
            expected = rec.get("before", current)
            conflict = not h.equal(current, value) and not h.equal(current, expected) and \
                h.user(ea, key, current) and current not in (None, "", [])
            if conflict:
                if on_conflict == "fail":
                    raise IdaxError(Exit.CONFLICT, f"{ea:#x}: {kind} is {current!r}, record expects "
                                    f"{expected!r} -> {value!r}", "CONFLICT")
                if on_conflict in ("skip", "ours"):
                    skipped += on_conflict == "skip"
                    out.append({"_t": "edit", "kind": kind, "ea": f"{ea:#x}" if ea is not None else None,
                                "key": key, "before": current, "after": value, "status": "skipped"})
                    continue
            r = edits.change(ctx, kind, ea, key, value, force=True,
                             record={"source_rev": rec.get("rev")} if rec.get("rev") else None)
            out.append(r)
    if skipped:
        ctx.set_status(Exit.PARTIAL)
    return finish(ctx, out)
