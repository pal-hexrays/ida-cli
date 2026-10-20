"""Function matching for ``diff`` and ``port`` (pure Python, testable).

Rounds run in the order given (default name, hash, lumina, structural):

name        the same non-dummy name on both sides
hash        the same operand-agnostic body hash, unique on both sides
flirt       library functions identified with the same name
lumina      functions both named by Lumina with the same name
structural  best score on callees, strings, constants and CFG shape, with
            call-graph propagation: a pair whose callees are already paired
            scores higher (quadratic in the functions left unmatched)
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

ROUNDS = ("name", "hash", "flirt", "lumina", "structural")
DEFAULT_ROUNDS = ("name", "hash", "lumina", "structural")


@dataclass
class Match:
    old: dict | None
    new: dict | None
    round: str | None = None
    similarity: float = 0.0
    changed_blocks: int = 0

    @property
    def diff(self) -> str:
        if self.old is None:
            return "added"
        if self.new is None:
            return "removed"
        same_body = self.old["hash"] == self.new["hash"]
        if same_body and self.old["name"] != self.new["name"] and not (
                self.old.get("dummy") and self.new.get("dummy")):
            return "renamed"
        if same_body:
            return "identical"
        return "changed"


def _jaccard(a: list | set, b: list | set) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.5  # no evidence either way

    return len(sa & sb) / len(sa | sb)


def _ratio(x: float, y: float) -> float:
    if x == y:
        return 1.0
    hi = max(x, y)
    return min(x, y) / hi if hi else 1.0


def block_overlap(a: list[str], b: list[str]) -> float:
    ca, cb = Counter(a), Counter(b)
    common = sum((ca & cb).values())
    total = max(sum(ca.values()), sum(cb.values()))
    return common / total if total else 1.0


def changed_blocks(a: list[str], b: list[str]) -> int:
    ca, cb = Counter(a), Counter(b)
    return max(sum((ca - cb).values()), sum((cb - ca).values()))


def similarity(o: dict, n: dict, paired_callees: float = 0.0) -> float:
    """0..1 similarity of two function fingerprints."""
    if o["hash"] == n["hash"]:
        return 1.0
    score = (
        0.30 * block_overlap(o["blocks"], n["blocks"])
        + 0.15 * _jaccard(o["callees"], n["callees"])
        + 0.15 * _jaccard(o["strings"], n["strings"])
        + 0.10 * _jaccard(o["consts"], n["consts"])
        + 0.10 * _ratio(o["insns"], n["insns"])
        + 0.10 * _ratio(len(o["blocks"]), len(n["blocks"]))
        + 0.05 * _ratio(o["edges"], n["edges"])
        + 0.05 * paired_callees
    )
    return round(min(score, 0.999), 4)


def match(old: list[dict], new: list[dict], rounds: tuple[str, ...] = DEFAULT_ROUNDS,
          threshold: float = 0.6) -> list[Match]:
    unknown = [r for r in rounds if r not in ROUNDS]
    if unknown:
        raise ValueError(f"unknown matching round(s): {', '.join(unknown)}")
    old = [f for f in old if not f.get("extern")]
    new = [f for f in new if not f.get("extern")]
    free_old = {f["ea"]: f for f in old}
    free_new = {f["ea"]: f for f in new}
    pairs: list[Match] = []

    def pair(o: dict, n: dict, rnd: str) -> None:
        free_old.pop(o["ea"], None)
        free_new.pop(n["ea"], None)
        pairs.append(Match(o, n, rnd, similarity(o, n), changed_blocks(o["blocks"], n["blocks"])))

    for rnd in rounds:
        if rnd in ("name", "flirt", "lumina"):
            def key(f: dict) -> str | None:
                if rnd == "name":
                    return f["name"] if not f.get("dummy") else None
                if rnd == "flirt":
                    return f["name"] if f.get("lib") else None
                return f["name"] if f.get("lumina") else None

            by_new: dict[str, list[dict]] = defaultdict(list)
            for f in free_new.values():
                k = key(f)
                if k:
                    by_new[k].append(f)
            for o in list(free_old.values()):
                k = key(o)
                if k and len(by_new.get(k, [])) == 1 and by_new[k][0]["ea"] in free_new:
                    pair(o, by_new[k][0], rnd)
        elif rnd == "hash":
            co = Counter(f["hash"] for f in free_old.values())
            cn = Counter(f["hash"] for f in free_new.values())
            by_hash = {f["hash"]: f for f in free_new.values() if cn[f["hash"]] == 1}
            for o in list(free_old.values()):
                if co[o["hash"]] == 1 and o["hash"] in by_hash and by_hash[o["hash"]]["ea"] in free_new:
                    pair(o, by_hash[o["hash"]], "hash")
        elif rnd == "structural":
            _structural(free_old, free_new, pairs, threshold, pair)
    for o in free_old.values():
        pairs.append(Match(o, None))
    for n in free_new.values():
        pairs.append(Match(None, n))
    def order(m: Match) -> int:
        if m.old is not None:
            return m.old["ea"]
        assert m.new is not None
        return (1 << 64) + m.new["ea"]

    pairs.sort(key=order)
    return pairs


def _structural(free_old: dict, free_new: dict, pairs: list[Match], threshold: float, pair: Any) -> None:
    """Greedy best-first assignment; scores include how many callees are
    already paired with each other (call-graph neighbourhood)."""
    while free_old and free_new:
        known = {m.old["name"]: m.new["name"] for m in pairs if m.old and m.new}
        best: tuple[float, dict, dict] | None = None
        for o in free_old.values():
            translated = [known.get(c, c) for c in o["callees"]]
            for n in free_new.values():
                if _ratio(o["size"], n["size"]) < 0.3:
                    continue
                neigh = _jaccard(translated, n["callees"]) if (translated or n["callees"]) else 0.0
                s = similarity(o, n, neigh)
                if best is None or s > best[0]:
                    best = (s, o, n)
        if best is None or best[0] < threshold:
            return
        pair(best[1], best[2], "structural")


@dataclass
class Summary:
    counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def of(cls, matches: list[Match]) -> "Summary":
        return cls(dict(Counter(m.diff for m in matches)))

    @property
    def identical(self) -> bool:
        return set(self.counts) <= {"identical"}
