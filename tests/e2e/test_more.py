"""End-to-end: automation, triage, storage, knowledge, export, compare,
meta and dynamic gating (adversarial)."""

import json
import shutil
import sqlite3

import pytest

from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

pytestmark = pytest.mark.ida


@pytest.fixture
def db(tmp_path, fresh):
    return ["-q", "--db", str(tmp_path / "t.i64")], str(fresh)


# -- automation -----------------------------------------------------------------------------

def test_exec_expression_entry_function_and_exit_codes(icli, db):
    g, f = db
    r = icli(*g, "exec", f, "-c", '[{"name": db.functions.get_name(x)} for x in db.functions if x.size() > 0x60]')
    assert r.code == 0 and {x["name"] for x in r.records} >= {"handle_kind", "parse_packet"}
    r = icli(*g, "exec", f, "-c", "def run(db):\n    return {'n': len(list(db.functions))}")
    assert r.record["n"] >= 10
    assert icli(*g, "exec", f, "-c", "import sys; sys.exit(7)").code == 7
    r = icli(*g, "exec", f, "-c", "1/0")
    assert r.code == 16 and "ZeroDivisionError" in r.err
    assert icli(*g, "exec", f, "-c", "def broken(:").code == 16


def test_exec_journals_and_undo_reverts_whole_exec(icli, db):
    g, f = db
    code = ("f = db.functions.get_function_by_name('unused_helper')\n"
            "db.functions.set_name(f, 'by_exec')\nimport ida_bytes\nida_bytes.set_cmt(f.start_ea, 'c', False)")
    assert icli(*g, "exec", f, "-c", code).code == 0
    log = icli(*g, "log", f).records
    assert log[-1]["kind"] == "exec" and len(log[-1]["changes"]) == 2
    assert icli(*g, "undo", f).code == 0
    assert icli(*g, "resolve", f, "unused_helper").code == 0


def test_exec_read_only_and_no_save_roll_back(icli, db):
    g, f = db
    code = "db.functions.set_name(db.functions.get_function_by_name('unused_helper'), 'zzz')"
    assert icli(*g, "exec", "--read-only", f, "-c", code).code == 13
    assert icli(*g, "exec", "--no-save", f, "-c", code).code == 0
    assert icli(*g, "resolve", f, "unused_helper").code == 0


def test_exec_each_args_json_and_idc(icli, db, tmp_path):
    g, f = db
    r = icli(*g, "exec", f, "--each", "func:*[size > 0x60]", "-c", '{"ea": ea, "n": item["name"]}')
    assert len(r.records) == 2
    script = tmp_path / "s.py"
    script.write_text("import sys\nsys.argv[1:]\n")
    r = icli(*g, "exec", f, str(script), "--", "--min-score", "7")
    assert [x["value"] for x in r.records] == ["--min-score", "7"]   # an iterable is a stream
    r = icli(*g, "-f", "json", "exec", f, "-c", "print('out'); 42")
    doc = json.loads(r.out)
    assert doc["stdout"] == "out\n" and doc["records"][0]["value"] == 42
    r = icli(*g, "exec", "--lang", "idc", f, "-c", "get_func_name(0x180)")
    assert r.record["value"] == "main"


def test_show_code_round_trips_through_exec(icli, db, tmp_path):
    g, f = db
    code = icli(*g, "--show-code", "list", "functions", "--where", "size > 0x60", f).out
    p = tmp_path / "gen.py"
    p.write_text(code)
    r = icli(*g, "exec", f, str(p))
    assert {x["name"] for x in r.records} == {"handle_kind", "parse_packet"}


def test_do_chain_percent_and_save_semantics(icli, db):
    g, f = db
    r = icli(*g, "do", f, "--", "search", "--crypto", "::", "tag", "%", "crypto", "::", "list", "tags")
    assert r.code == 0 and r.records[-1]["tag"] == "crypto"
    r = icli(*g, "do", f, "--", "rename", "--force", "unused_helper", "chained", "::", "rename", "nope_x", "y")
    assert r.code == 5
    assert icli(*g, "resolve", f, "chained").code == 5         # not saved: a step failed
    r = icli(*g, "do", "--keep-going", f, "--", "rename", "--force", "unused_helper", "chained", "::",
             "rename", "nope_x", "y")
    assert icli(*g, "resolve", f, "chained").code == 0         # --keep-going saves
    icli(*g, "do", "--no-save", f, "--", "rename", "--force", "chained", "discarded")
    assert icli(*g, "resolve", f, "discarded").code == 5
    assert icli(*g, "do", f, "--", "do", f).code == 2           # chains do not nest
    assert icli(*g, "do", f).code == 2                          # no steps


def test_do_recipe(icli, db, tmp_path):
    g, f = db
    rdir = tmp_path / "home" / "icli" / "recipes"
    rdir.mkdir(parents=True)
    out = tmp_path / "{input}.sarif"
    (rdir / "triage.icli").write_text(f"# comment\nlist functions --count\nexport sarif -o {out} func:main\n")
    r = icli(*g, "do", f, "@triage", env={"ICLI_HOME": str(tmp_path / "home")})
    assert r.code == 0 and (tmp_path / "sample.o.sarif").exists()
    assert icli(*g, "do", f, "@missing", env={"ICLI_HOME": str(tmp_path / "home")}).code == 4


def test_batch_tags_steps(icli, db):
    g, f = db
    r = icli(*g, "batch", f, "-", stdin="list functions --count\n# skipped\nresolve main\n")
    assert [x["step"] for x in r.records] == [1, 2]


def test_assert_and_ref(icli, db):
    g, f = db
    assert icli(*g, "assert", f, "func:*[size > 0x60]", "<= 2").code == 0
    r = icli(*g, "assert", f, "func:*[size > 0x60]", "== 0")
    assert r.code == 1 and r.records[0]["count"] == 2
    assert icli(*g, "assert", f, "func:*", "about 3").code == 2
    r = icli("ref", "-n", "2", "-f", "jsonl", "rename local variable")
    assert r.code == 0 and len(r.records) == 2 and all(x["signature"] for x in r.records)
    assert icli("ref").code == 2


# -- triage -----------------------------------------------------------------------------------

def test_identify_loaders_processors_version(icli, workdir, tmp_path):
    r = icli("identify", "--hash", "md5,sha256,ssdeep", "sample.o", "crackme03.elf")
    recs = r.records
    assert r.code == 0 and recs[0]["loader"] == "elf" and recs[1]["build_id"]
    junk = tmp_path / "junk.txt"
    junk.write_text("not a binary")
    assert icli("identify", str(junk)).code == 1
    assert icli("identify", "--hash", "crc99", "sample.o").code == 2
    assert icli("identify", "nope.bin").code == 4
    r = icli("loaders", "sample.o")
    assert r.record["loader"] == "elf"
    r = icli("processors", "arm")
    assert r.record["decompiler"]
    assert icli("processors", "zz-no-such-cpu").code == 1
    r = icli("--version")
    assert r.code == 0 and "kernel" in r.out


# -- storage -----------------------------------------------------------------------------------

def test_db_path_creates_nothing_and_cache(icli, tmp_path, cache_dir):
    src = tmp_path / "x.o"
    shutil.copy(FIXTURES / "crackme03.elf", src)
    r = icli("db", "path", str(src))
    assert r.code == 0 and not r.record["exists"]
    key = r.record["key"]
    assert icli("cache", "key", str(src)).record["key"] == key
    icli("info", str(src))
    assert any(e["key"] == key for e in icli("cache", "ls").records)
    assert icli("cache", "rm", str(src)).code == 0
    assert not icli("db", "path", str(src)).record["exists"]
    assert icli("cache", "prune").code == 2


def test_db_create_tag_copy_check(icli, tmp_path):
    out = tmp_path / "made.i64"
    r = icli("db", "create", "-o", str(out), "sample.o")
    assert r.code == 0 and out.exists()
    assert icli("db", "create", "-o", str(out), "sample.o").code == 9
    assert icli("db", "tag", "made", str(out)).code == 0
    assert icli("list", "functions", "--count", "@made").record["count"] > 0
    assert icli("db", "copy", str(out), str(tmp_path / "copy.i64")).code == 0
    assert icli("db", "check", str(tmp_path / "copy.i64")).record["ok"]
    assert icli("db", "tag", "bad name", str(out)).code == 2


def test_load_option_on_existing_database_is_usage(icli, tmp_path):
    out = tmp_path / "m.i64"
    icli("db", "create", "-o", str(out), "sample.o")
    assert icli("--processor", "arm", "info", str(out)).code == 2


def test_serve_forwarding_and_sessions(icli, tmp_path):
    src = tmp_path / "srv.o"
    shutil.copy(FIXTURES / "sample.o", src)
    r = icli("serve", "--detach", "--idle-timeout", "2m", str(src))
    assert r.code == 0
    try:
        assert icli("list", "functions", "--count", str(src)).record["count"] > 0
        icli("exec", str(src), "--session", "s1", "-c", "counter = 41")
        assert icli("exec", str(src), "--session", "s1", "-c", "counter + 1").record["value"] == 42
        assert icli("exec", str(src), "-c", "counter").code == 16      # sessions are opt-in
        assert icli("serve", "--detach", str(src)).code == 11          # already served
    finally:
        assert icli("serve", "--stop", str(src)).code == 0
    assert icli("exec", str(src), "--session", "s1", "-c", "1").code == 2


# -- knowledge -------------------------------------------------------------------------------

def test_sig_make_apply_list_and_collisions(icli, tmp_path):
    out = tmp_path / "s.sig"
    r = icli("sig", "make", "--library-name", "icli test", "-o", str(out), "sample.o")
    assert r.code == 0 and r.record["functions"] > 3
    g = ["--db", str(tmp_path / "a.i64")]
    r = icli(*g, "sig", "apply", "sample.o", str(out))
    assert r.record["matches"] > 3 and r.record["title"] == "icli test"
    assert icli(*g, "sig", "apply", "sample.o", "no_such_sig").code == 4
    assert icli("sig", "list", "--processor", "pc").code == 0
    pat = tmp_path / "s.pat"
    assert icli("sig", "make", "--pat-only", "-o", str(pat), "sample.o").code == 0
    assert pat.read_text().rstrip().endswith("---")


def test_til_make_dump_merge_export(icli, tmp_path):
    h = tmp_path / "w.h"
    h.write_text("struct widget { int id; char name[16]; };\ntypedef struct widget widget_t;\n")
    til = tmp_path / "w.til"
    assert icli("til", "make", "-o", str(til), str(h)).record["types"] == 2
    assert "struct widget" in icli("-f", "raw", "til", "dump", str(til)).out
    assert icli("til", "dump", str(til), "nope").code == 5
    assert icli("til", "merge", "-o", str(tmp_path / "m.til"), str(til)).record["types"] == 2
    g = ["--db", str(tmp_path / "e.i64")]
    icli(*g, "type", "add", "sample.o", "-", stdin="struct exported_t { int x; };")
    assert icli(*g, "til", "export", "sample.o", "-o", str(tmp_path / "l.til")).record["types"] >= 1


def test_load_names_map_coverage_binary(icli, tmp_path):
    g = ["--db", str(tmp_path / "l.i64")]
    names = tmp_path / "n.csv"
    names.write_text("0x170,loaded_name\n")
    assert icli(*g, "load", "names", "sample.o", str(names)).code == 0
    assert icli(*g, "resolve", "sample.o", "loaded_name").code == 0
    cov = tmp_path / "c.txt"
    cov.write_text("0x180 3\n0x188\n")
    assert icli(*g, "load", "coverage", "sample.o", str(cov)).code == 0
    r = icli(*g, "list", "functions", "sample.o", "--where", "coverage > 0", "--fields", "name,coverage")
    assert r.record["name"] == "main" and r.record["coverage"] == 4
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x90" * 64)
    assert icli(*g, "load", "binary", "sample.o", str(blob)).code == 2      # --at required
    assert icli(*g, "load", "binary", "--at", "0x10000", "sample.o", str(blob)).code == 0
    assert icli(*g, "-f", "text", "list", "segments", "sample.o", "--where", "ea == 0x10000").code == 0


# -- export ------------------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["asm", "lst", "html", "map", "idc", "python", "journal", "dif", "c", "cpp", "mc",
                                 "h", "til", "pat", "dot", "gdl", "svg", "sarif", "sig", "exe", "bin", "i64"])
def test_export_every_format_to_a_file(icli, tmp_path, fmt):
    out = tmp_path / f"out.{fmt}"
    r = icli("export", fmt, "-o", str(out), "sample.o")
    assert r.code == 0, r.err
    assert out.exists() and (out.stat().st_size > 0 or fmt == "journal")


def test_export_stdout_templates_and_usage(icli, tmp_path):
    r = icli("export", "c", "sample.o", "parse_packet")
    assert r.code == 0 and "parse_packet" in r.out and not r.out.startswith("{")
    r = icli("export", "c", "-o", str(tmp_path / "src" / "{name}.c"), "sample.o", "func:*[size > 0x60]")
    assert sorted(p.name for p in (tmp_path / "src").iterdir()) == ["handle_kind.c", "parse_packet.c"]
    assert icli("export", "map", "sample.o", "main").code == 2              # map takes no selector
    assert icli("export", "exe", "--in-place", "sample.o").code == 2        # needs --force
    assert icli("export", "sqlite", "sample.o").code == 2                   # needs -o


def test_export_sqlite_and_minimal_i64(icli, tmp_path):
    dbp = tmp_path / "app.db"
    assert icli("export", "sqlite", "-o", str(dbp), "sample.o").code == 0
    rows = sqlite3.connect(dbp).execute("SELECT name FROM functions WHERE callers = 0").fetchall()
    assert ("main",) in rows
    repro = tmp_path / "repro.i64"
    assert icli("export", "i64", "-o", str(repro), "sample.o", "parse_packet").code == 0
    r = icli("decompile", str(repro), "parse_packet")
    assert r.code == 0 and "memcpy" in r.record["pseudocode"]


def test_export_patched_input(icli, tmp_path):
    g = ["--db", str(tmp_path / "p.i64")]
    icli(*g, "patch", "bytes", "sample.o", "substitute", "4889")
    out = tmp_path / "patched.o"
    assert icli(*g, "export", "exe", "-o", str(out), "sample.o").record["patched_bytes"] == 2
    original = (FIXTURES / "sample.o").read_bytes()
    patched = out.read_bytes()
    assert len(original) == len(patched) and original != patched


# -- compare -------------------------------------------------------------------------------------

def test_diff_classes_exit_status_and_journal(icli, workdir, tmp_path):
    shutil.copy(FIXTURES / "sample_v2.o", workdir / "sample_v2.o")
    r = icli("diff", "sample.o", "sample_v2.o")
    assert r.code == 1
    classes = {x["name"]: x["diff"] for x in r.records}
    assert classes["parse_packet"] == "changed" and classes["unused_helper"] == "removed"
    assert classes["checksum"] == "added" and classes["main"] == "identical"
    assert icli("diff", "sample.o", "sample.o").code == 0
    r = icli("diff", "--pseudocode", "sample.o", "sample_v2.o")
    assert any(x.get("patch", "").startswith("---") for x in r.records)
    assert icli("diff", "--match", "magic", "sample.o", "sample_v2.o").code == 2
    assert icli("diff", "sample.o").code == 2


def test_port_carries_annotations(icli, workdir, tmp_path):
    shutil.copy(FIXTURES / "sample_v2.o", workdir / "sample_v2.o")
    a, b = ["--db", str(tmp_path / "a.i64")], ["--db", str(tmp_path / "b.i64")]
    icli(*a, "rename", "--force", "sample.o", "substitute", "sbox_sub")
    icli(*a, "export", "i64", "-o", str(tmp_path / "old.i64"), "sample.o")
    icli(*b, "info", "sample_v2.o")
    r = icli("port", str(tmp_path / "old.i64"), str(tmp_path / "b.i64"))
    assert r.code == 0 and any(x["after"] == "sbox_sub" for x in r.records)
    assert icli("resolve", str(tmp_path / "b.i64"), "sbox_sub").code == 0


# -- meta and dynamic gating ----------------------------------------------------------------------

def test_help_topics_and_commands(icli):
    assert "SELECTORS" in icli("help", "selectors").out
    assert "EXIT STATUS" in icli("help", "exit-codes").out
    assert "icli decompile" in icli("help", "decompile").out
    assert icli("help", "no-such-topic").code == 2


def test_config_roundtrip(icli, tmp_path):
    env = {"ICLI_HOME": str(tmp_path)}
    assert icli("config", "set", "--global", "defaults.addr", "rva", env=env).code == 0
    assert icli("-f", "text", "config", "get", "--global", "defaults.addr", env=env).out.strip() == "rva"
    r = icli("resolve", "sample.o", "main", env=env)
    assert r.record["ea"].startswith("rva:")
    assert icli("config", "set", "--global", "ida.NO_SUCH_KEY", "1", env=env).code == 2
    assert icli("config", "unset", "--global", "defaults.addr", env=env).code == 0
    assert icli("config", "get", "--global", "defaults.addr", env=env).code == 1


def test_set_validation(icli):
    assert icli("--set", "NO_SUCH_DIRECTIVE=1", "info", "sample.o").code == 2
    assert icli("--set", "hexrays.NOPE=1", "info", "sample.o").code == 2
    assert icli("--set", "garbage", "info", "sample.o").code == 2


def test_schema_and_completion(icli):
    r = icli("-f", "jsonl", "schema", "list", "functions")
    s = r.record
    assert s["$id"] == "icli.function/1" and "cyclomatic" in s["properties"]
    assert icli("schema", "frobnicate").code == 2
    assert "complete" in icli("completion", "bash").out
    assert "decompile" in icli("__complete", "--", "dec").out.split()


def test_dynamic_commands_need_allow_execute(icli):
    assert icli("debug", "run", "sample.o").code == 2
    assert icli("trace", "sample.o").code == 2
    assert icli("debug", "attach", "sample.o").code == 2


LEGACY_IDBS = [Path.home() / "devel/projects/hexrays/python-idb/tests/data/elf/ls.idb",
               Path.home() / "devel/projects/hexrays/idb-rs/resources/idbs/func_comment.idb"]


@pytest.mark.parametrize("src", LEGACY_IDBS, ids=lambda p: p.name)
def test_legacy_idb_upgrade(icli, tmp_path, src):
    """IDA 9 cannot create a 32-bit .idb, so these use local legacy samples."""
    if not src.exists():
        pytest.skip(f"no legacy sample {src}")
    old = tmp_path / src.name
    shutil.copy(src, old)
    out = tmp_path / "up.i64"
    r = icli("db", "upgrade", "-o", str(out), str(old))
    assert r.code == 0 and out.exists()
    assert icli("list", "functions", "--count", str(out)).record["count"] > 0
    assert icli("db", "upgrade", "-o", str(out), str(old)).code == 9          # never overwrites
    other = tmp_path / "again.idb"
    shutil.copy(src, other)
    assert icli("list", "functions", "--count", str(other)).code == 0          # upgraded on first use
