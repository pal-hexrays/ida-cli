"""Adversarial tests for function matching."""

import pytest

from icli.lang.diffing import Summary, match, similarity


def fn(ea, name, h, blocks=("a",), callees=(), strings=(), consts=(), dummy=False, lib=False, insns=10,
       size=40, extern=False):
    return {"ea": ea, "name": name, "hash": h, "blocks": list(blocks), "edges": len(blocks) - 1,
            "callees": list(callees), "strings": list(strings), "consts": list(consts), "dummy": dummy,
            "lib": lib, "insns": insns, "size": size, "extern": extern, "lumina": False}


def test_identical_and_renamed_and_added_removed():
    old = [fn(0x10, "main", "h1"), fn(0x20, "sub_20", "h2", dummy=True),
           fn(0x30, "gone", "h3", blocks=("p", "q"), callees=("free",), insns=12)]
    new = [fn(0x10, "main", "h1"), fn(0x28, "parse", "h2"),
           fn(0x40, "fresh", "h4", blocks=("r",) * 6, strings=("new",), consts=(99,), insns=80, size=200)]
    ms = match(old, new)
    d = {((m.old or {}).get("name"), (m.new or {}).get("name")): m.diff for m in ms}
    assert d[("main", "main")] == "identical"
    assert d[("sub_20", "parse")] == "renamed"
    assert d[("gone", None)] == "removed"
    assert d[(None, "fresh")] == "added"
    assert not Summary.of(ms).identical


def test_hash_round_requires_uniqueness():
    # two old functions with the same body: hash matching must not guess
    old = [fn(1, "sub_1", "dup", dummy=True), fn(2, "sub_2", "dup", dummy=True)]
    new = [fn(9, "sub_9", "dup", dummy=True)]
    ms = match(old, new, rounds=("hash",))
    assert sum(1 for m in ms if m.old and m.new) == 0


def test_name_round_ignores_dummy_names():
    old = [fn(1, "sub_1", "x", dummy=True)]
    new = [fn(2, "sub_1", "y", dummy=True)]
    ms = match(old, new, rounds=("name",))
    assert all(m.old is None or m.new is None for m in ms)


def test_structural_threshold_and_changed_blocks():
    o = fn(1, "f", "h_old", blocks=("a", "b", "c", "d"), callees=("memcpy",), strings=("hi",), insns=40)
    n = fn(2, "f2", "h_new", blocks=("a", "b", "c", "e"), callees=("memcpy",), strings=("hi",), insns=42)
    ms = match([o], [n], rounds=("structural",), threshold=0.6)
    m = next(x for x in ms if x.old and x.new)
    assert m.diff == "changed" and 0.6 <= m.similarity < 1 and m.changed_blocks == 1
    # an unrelated function stays unmatched
    u = fn(3, "u", "zz", blocks=("q",) * 9, callees=("recv",), strings=("x",), consts=(7,), insns=200, size=400)
    ms = match([o], [u], rounds=("structural",), threshold=0.6)
    assert all(not (m.old and m.new) for m in ms)


def test_extern_functions_are_ignored():
    ms = match([fn(1, "puts", "e", extern=True)], [fn(1, "puts", "e", extern=True)])
    assert ms == []


def test_similarity_bounds():
    a = fn(1, "a", "h", blocks=("x",))
    assert similarity(a, a) == 1.0
    b = fn(2, "b", "other", blocks=("y",) * 5, insns=99)
    assert 0 <= similarity(a, b) < 0.6


def test_unknown_round_rejected():
    with pytest.raises(ValueError):
        match([], [], rounds=("nonsense",))
