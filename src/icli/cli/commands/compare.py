"""Compare: diff and port."""

from __future__ import annotations

import argparse
import difflib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ...errors import Exit, usage
from ...lang import diffing
from ..registry import Command, Invocation, register


def _rounds(text: str | None) -> tuple[str, ...]:
    if not text:
        return diffing.DEFAULT_ROUNDS
    rounds = tuple(r.strip() for r in text.split(",") if r.strip())
    bad = [r for r in rounds if r not in diffing.ROUNDS]
    if bad:
        raise usage(f"--match: unknown round(s) {', '.join(bad)} (one of {', '.join(diffing.ROUNDS)})")
    return rounds


def open_pair(inv: Invocation, old: str, new: str) -> tuple[Any, Any]:
    from ..opening import open_session

    with ThreadPoolExecutor(max_workers=2) as pool:
        fo = pool.submit(open_session, old, inv.g, inv.emitter.diag)
        fn = pool.submit(open_session, new, inv.g, inv.emitter.diag)
        so = fo.result()
        try:
            sn = fn.result()
        except BaseException:
            so.close()
            raise
    return so, sn


def fingerprints(so: Any, sn: Any) -> tuple[list[dict], list[dict]]:
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(lambda: so.call("diff.fingerprint", {})["records"])
        b = pool.submit(lambda: sn.call("diff.fingerprint", {})["records"])
        return a.result(), b.result()


def port_records(so: Any, matches: list[diffing.Match], what: list[str]) -> list[dict]:
    """Journal records carrying old's annotations onto the matched new functions."""
    pairs = [m for m in matches if m.old and m.new]
    if not pairs:
        return []
    ann = {a["ea"]: a for a in so.call("diff.annotations", {"eas": [m.old["ea"] for m in pairs],
                                                            "what": what})["records"]}
    out: list[dict] = []
    for m in pairs:
        a = ann.get(m.old["ea"])
        if not a:
            continue
        new_ea = m.new["ea"]
        same_layout = m.old["hash"] == m.new["hash"]
        base = {"_t": "journal", "source": "diff", "similarity": m.similarity}
        if a.get("name") and a["name"] != m.new["name"]:
            out.append({**base, "kind": "name", "ea": f"{new_ea:#x}", "key": None, "before": m.new["name"],
                        "after": a["name"]})
        if a.get("type"):
            out.append({**base, "kind": "type", "ea": f"{new_ea:#x}", "key": None, "after": a["type"]})
        if a.get("function_comment"):
            out.append({**base, "kind": "comment", "ea": f"{new_ea:#x}", "key": "function",
                        "after": a["function_comment"]})
        if same_layout:  # instruction comments only where the bodies line up
            for c in a.get("comments", []):
                out.append({**base, "kind": "comment", "ea": f"{new_ea + c['off']:#x}", "key": c["kind"],
                            "after": c["text"]})
        if a.get("tags"):
            out.append({**base, "kind": "tags", "ea": f"{new_ea:#x}", "key": None, "after": a["tags"]})
    return out


@register
class Diff(Command):
    name = "diff"
    group = "compare"
    summary = "compare two databases function by function"
    target = "none"

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="old new")
        p.add_argument("--match", metavar="ROUND[,ROUND...]", help=", ".join(diffing.ROUNDS))
        p.add_argument("--threshold", type=float, default=0.6, metavar="SCORE")
        p.add_argument("--pseudocode", action="store_true")
        p.add_argument("--asm", action="store_true")
        p.add_argument("--emit-journal", metavar="FILE")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        if len(a.items) != 2:
            raise usage("icli diff: expected OLD NEW")
        if not 0 <= a.threshold <= 1:
            raise usage("--threshold must be between 0 and 1")
        rounds = _rounds(a.match)
        so, sn = open_pair(inv, a.items[0], a.items[1])
        try:
            fo, fn = fingerprints(so, sn)
            matches = diffing.match(fo, fn, rounds, a.threshold)
            patches: dict[int, str] = {}
            changed = [m for m in matches if m.diff == "changed"]
            if changed and (a.pseudocode or a.asm):
                kind = "pseudocode" if a.pseudocode else "asm"
                to = {r["ea"]: r["text"] for r in so.call("diff.text", {"eas": [m.old["ea"] for m in changed],
                                                                       "kind": kind})["records"]}
                tn = {r["ea"]: r["text"] for r in sn.call("diff.text", {"eas": [m.new["ea"] for m in changed],
                                                                       "kind": kind})["records"]}
                for m in changed:
                    patches[id(m)] = "".join(difflib.unified_diff(
                        to[m.old["ea"]].splitlines(True), tn[m.new["ea"]].splitlines(True),
                        f"a/{m.old['name']}", f"b/{m.new['name']}"))
            if a.emit_journal:
                recs = port_records(so, matches, ["names", "types", "comments", "tags"])
                Path(a.emit_journal).write_text("".join(json.dumps(r) + "\n" for r in recs))
        finally:
            so.close()
            sn.close()
        out = []
        for m in matches:
            rec = {"_t": "diff", "diff": m.diff, "similarity": round(m.similarity, 4) if m.old and m.new else 0.0,
                   "ea": f"{m.old['ea']:#x}" if m.old else None, "other_ea": f"{m.new['ea']:#x}" if m.new else None,
                   "name": (m.old or m.new)["name"], "other_name": m.new["name"] if m.new else None,
                   "changed_blocks": m.changed_blocks, "round": m.round}
            if id(m) in patches:
                rec["patch"] = patches[id(m)]
            out.append(rec)
        inv.emit(out)
        summary = diffing.Summary.of(matches)
        inv.emitter.diag("info", "DIFF", ", ".join(f"{k} {v}" for k, v in sorted(summary.counts.items())))
        return 0 if summary.identical else Exit.NEGATIVE


@register
class Port(Command):
    name = "port"
    group = "compare"
    summary = "carry annotations from an analysed build onto a new one"
    target = "none"
    edits = True

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*", metavar="from to")
        p.add_argument("--what", default="names,types,comments,tags", metavar="names,types,comments,tags")
        p.add_argument("--match", metavar="ROUND[,ROUND...]")
        p.add_argument("--threshold", type=float, default=0.6)
        p.add_argument("--message", "-m", metavar="TEXT")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        if len(a.items) != 2:
            raise usage("icli port: expected FROM TO")
        what = [w.strip() for w in a.what.split(",") if w.strip()]
        bad = [w for w in what if w not in ("names", "types", "comments", "tags")]
        if bad:
            raise usage(f"--what: unknown {', '.join(bad)}")
        so, sn = open_pair(inv, a.items[0], a.items[1])
        try:
            fo, fn = fingerprints(so, sn)
            matches = diffing.match(fo, fn, _rounds(a.match), a.threshold)
            recs = port_records(so, matches, what)
            if not recs:
                inv.emitter.diag("info", "PORT", "nothing to port")
                return 0
            res = sn.call("apply", {"records": recs, "on_conflict": "skip"},
                          ctx=inv.engine_ctx(message=a.message or f"port from {a.items[0]}"))
            for w in res.get("warnings", []):
                inv.emitter.diag(w["level"], w["code"], w["msg"])
            records = res.get("records", [])
            changed = [r for r in records if r.get("status") != "unchanged"]
            inv.emit(changed)
            inv.emitter.diag("info", "PORT", f"{len(changed)} change(s), {len(records) - len(changed)} already "
                                             "present")
            sn.dirty = True
            return int(res.get("status", 0))
        finally:
            so.close()
            sn.close()
