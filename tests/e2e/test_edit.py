"""End-to-end edits and the journal (adversarial: idempotency, conflicts,
dry runs, undo, replay, read-only)."""

import json

import pytest

pytestmark = pytest.mark.ida


@pytest.fixture
def db(tmp_path, fresh):
    """Global options pinning a private database for the fresh input copy."""
    return ["-q", "--db", str(tmp_path / "edit.i64")], str(fresh)


def test_rename_idempotent_conflict_force(icli, db):
    g, f = db
    r = icli(*g, "rename", f, "unused_helper", "x")
    assert r.code == 9 and "--force" in r.err          # loader symbols count as user names
    r = icli(*g, "rename", "--force", f, "unused_helper", "triple")
    assert r.code == 0 and r.record["status"] == "changed"
    r = icli(*g, "rename", f, "triple", "triple")
    assert r.code == 0 and r.record["status"] == "unchanged"
    r = icli(*g, "rename", f, "triple", "other")
    assert r.code == 9
    r = icli(*g, "--dry-run", "rename", "--force", f, "triple", "other")
    assert r.code == 0 and r.record["status"] == "would-change"
    r = icli(*g, "--dry-run", "rename", f, "triple", "triple")
    assert r.code == 1
    # the dry run changed nothing
    assert icli(*g, "resolve", f, "triple").code == 0


def test_rename_collision_and_unique(icli, db):
    g, f = db
    r = icli(*g, "rename", "--force", f, "unused_helper", "main")
    assert r.code == 9 and "already used" in r.err
    r = icli(*g, "rename", "--force", "--unique", f, "unused_helper", "main")
    assert r.code == 0 and r.record["name"] == "main_1"


def test_rename_template_and_map(icli, db, tmp_path):
    g, f = db
    r = icli(*g, "rename", "--force", f, "func:check_*", "fn_{size}_{name}")
    assert r.record["name"] == "fn_30_check_update"
    m = tmp_path / "map.tsv"
    m.write_text("main\tentry_main\n# comment\n\nsubstitute\tsbox_lookup\n")
    r = icli(*g, "rename", "--force", f, str(m))
    assert r.code == 0 and {x["name"] for x in r.records} == {"entry_main", "sbox_lookup"}
    r = icli(*g, "rename", "--force", f, "-", stdin='{"ea": "0x180", "name": "main"}\n')
    assert r.record["name"] == "main"


def test_rename_bad_map_line_is_usage(icli, db, tmp_path):
    g, f = db
    m = tmp_path / "bad.tsv"
    m.write_text("main entry_main\n")
    assert icli(*g, "rename", f, str(m)).code == 2


def test_rename_regex_and_clear(icli, db):
    g, f = db
    r = icli(*g, "rename", "--force", "--regex", "s/^check_(.*)$/verify_$1/", f, "func:check_*")
    assert r.record["name"] == "verify_update"
    r = icli(*g, "rename", "--force", "--clear", f, "verify_update")
    assert r.code == 0 and r.record["name"] != "verify_update"


def test_rename_local_variable(icli, db):
    g, f = db
    r = icli(*g, "rename", "--lvar", "parse_packet", f, "a1", "pkt")
    assert r.code == 0 and r.record["status"] == "changed"
    r = icli(*g, "rename", "--lvar", "parse_packet", f, "a1", "pkt")
    assert r.record["status"] == "unchanged"
    d = icli(*g, "decompile", f, "parse_packet")
    assert "pkt" in d.record["pseudocode"]
    assert icli(*g, "rename", "--lvar", "parse_packet", f, "nonexistent_var", "y").code == 5


def test_comment_kinds_append_remove(icli, db):
    g, f = db
    assert icli(*g, "comment", f, "main", "first").code == 0
    r = icli(*g, "comment", "--append", f, "main", "second")
    assert r.record["after"] == "first\nsecond"
    r = icli(*g, "comment", "--append", f, "main", "second")
    assert r.record["status"] == "unchanged"
    r = icli(*g, "comment", f, "main", "")
    assert r.record["after"] is None
    r = icli(*g, "comment", "--kind", "pseudocode", f, "parse_packet+0x45", "S-box")
    assert r.code == 0
    d = icli(*g, "decompile", f, "parse_packet")
    assert "S-box" in d.record["pseudocode"]
    assert icli(*g, "comment", "--kind", "bogus", f, "main", "x").code == 2


def test_type_add_set_conflict_replace(icli, db, tmp_path):
    g, f = db
    h = tmp_path / "pkt.h"
    h.write_text("struct pkt { unsigned char kind; unsigned char flags; unsigned short len;"
                 " unsigned char body[60]; };\ntypedef struct pkt pkt_t;\n")
    assert icli(*g, "type", "add", f, str(h)).code == 0
    r = icli(*g, "type", "add", f, str(h))
    assert r.code == 0 and all(x["status"] == "unchanged" for x in r.records)
    r = icli(*g, "type", "add", f, "-", stdin="struct pkt { int different; };")
    assert r.code == 9
    r = icli(*g, "type", "set", f, "parse_packet", "int __fastcall parse_packet(pkt_t *p, unsigned long n)")
    assert r.code == 0
    assert "pkt_t *p" in icli(*g, "type", "get", f, "parse_packet").record["type"]
    assert icli(*g, "type", "set", f, "parse_packet", "this is not C").code == 2
    dump = icli(*g, "-f", "raw", "type", "dump", f)
    assert "struct pkt" in dump.out
    assert icli(*g, "type", "del", f, "pkt_t").code == 0
    assert icli(*g, "type", "dump", f, "pkt_t").code == 5


def test_tags_and_colour(icli, db):
    g, f = db
    r = icli(*g, "tag", "--color", "ffe0e0", f, "callers(imp:*!memcpy)", "crypto")
    assert r.code == 0
    r = icli(*g, "resolve", f, "tag:crypto")
    assert [x["name"] for x in r.records] == ["parse_packet"]
    assert icli(*g, "tag", "--color", "red", f, "main", "x").code == 2
    r = icli(*g, "tag", "--remove", f, "parse_packet", "crypto")
    assert r.code == 0
    assert icli(*g, "resolve", f, "tag:crypto").code == 1


def test_patch_bytes_nop_revert(icli, db):
    g, f = db
    r = icli(*g, "patch", "bytes", f, "substitute+2", "90 90")
    assert r.code == 0
    r = icli(*g, "patch", "bytes", f, "substitute+2", "9090")
    assert r.code == 0 and r.record["status"] == "unchanged"
    assert icli(*g, "list", "patches", f).record["patched"] == "9090"
    r = icli(*g, "patch", "nop", f, "substitute")
    assert r.code == 0
    r = icli(*g, "patch", "revert", f)
    assert r.code == 0
    assert icli(*g, "list", "patches", f).out == ""
    assert icli(*g, "patch", "bytes", f, "main", "zz").code == 2


def test_patch_asm(icli, db):
    g, f = db
    r = icli(*g, "patch", "asm", f, "substitute", "nop", "nop")
    assert r.code == 0 and len(r.records) == 2
    assert icli(*g, "patch", "asm", f, "substitute", "not an instruction").code == 2


def test_func_create_delete_flags(icli, db):
    g, f = db
    r = icli(*g, "func", "set", f, "unused_helper", "--flags", "+noret")
    assert r.code == 0
    assert "NORET" in icli(*g, "list", "functions", f, "--match", "unused_helper").record["flags"]
    assert icli(*g, "func", "set", f, "unused_helper", "--flags", "+bogus").code == 2
    assert icli(*g, "func", "delete", f, "unused_helper").code == 0
    assert icli(*g, "list", "functions", f, "--match", "unused_helper").out == ""
    assert icli(*g, "func", "create", f, "0x170").code == 0
    assert icli(*g, "list", "functions", f, "--match", "unused_helper").code == 0


def test_make_items(icli, db):
    g, f = db
    r = icli(*g, "make", "unknown", f, "substitute")
    assert r.code == 0
    r = icli(*g, "make", "code", f, "substitute")
    assert r.code == 0
    r = icli(*g, "make", "array", f, "aes_sbox", "--count", "256")
    assert r.code == 0
    assert icli(*g, "make", "array", f, "aes_sbox").code == 2


def test_log_undo_and_apply_replay(icli, db, tmp_path):
    g, f = db
    icli(*g, "rename", "--force", f, "unused_helper", "one")
    icli(*g, "comment", f, "main", "note")
    log = icli(*g, "log", f)
    revs = [x["rev"] for x in log.records]
    assert revs == sorted(revs) and len(revs) >= 2
    r = icli(*g, "undo", f, "-n", "2")
    assert r.code == 0
    assert icli(*g, "resolve", f, "unused_helper").code == 0
    # replay the original journal (records carry after values)
    journal = "\n".join(json.dumps(x) for x in log.records[:2])
    r = icli(*g, "apply", f, "-", stdin=journal)
    assert r.code == 0
    assert icli(*g, "resolve", f, "one").code == 0
    # replay again: idempotent
    r = icli(*g, "apply", f, "-", stdin=journal)
    assert all(x["status"] == "unchanged" for x in r.records)
    assert icli(*g, "undo", f, "--to", "99999").code == 2


def test_apply_conflict_policies(icli, db):
    g, f = db
    icli(*g, "rename", "--force", f, "unused_helper", "mine")
    foreign = json.dumps({"kind": "name", "ea": "0x170", "before": "unused_helper", "after": "theirs"})
    assert icli(*g, "apply", f, "-", stdin=foreign).code == 9
    r = icli(*g, "apply", "--on-conflict", "skip", f, "-", stdin=foreign)
    assert r.code == 3 and r.record["status"] == "skipped"
    r = icli(*g, "apply", "--on-conflict", "theirs", f, "-", stdin=foreign)
    assert r.code == 0 and r.record["status"] == "changed"
    # query records with ea+name are accepted too, --only filters kinds
    q = json.dumps({"_t": "function", "ea": "0x170", "name": "q_name", "comment": "c"})
    r = icli(*g, "apply", "--only", "comment", f, "-", stdin=q)
    assert [x["kind"] for x in r.records] == ["comment"]


def test_read_only_refuses_edits(icli, db):
    g, f = db
    icli(*g, "info", f)
    r = icli(*g, "--read-only", "comment", f, "main", "x")
    assert r.code == 13


def test_edits_persist_across_invocations(icli, db):
    g, f = db
    icli(*g, "rename", "--force", f, "unused_helper", "persisted")
    r = icli(*g, "list", "functions", f, "--match", "persisted")
    assert r.record["name"] == "persisted"
