"""End-to-end query commands against real idalib workers (adversarial)."""

import json

import pytest

pytestmark = pytest.mark.ida


def test_first_contact_decompile_then_cached(icli):
    r = icli("decompile", "sample.o", "parse_packet")
    assert r.code == 0, r.err
    rec = r.record
    assert rec["status"] == "ok" and "memcpy" in rec["pseudocode"]
    # second run reuses the cached, analysed database: no "loading" message
    r2 = icli("decompile", "sample.o", "parse_packet")
    assert r2.code == 0 and "loading" not in r2.err


def test_missing_input_is_status_4(icli):
    r = icli("info", "no-such-file.bin")
    assert r.code == 4 and "no such file" in r.err


def test_missing_database_is_status_4(icli):
    assert icli("info", "nope.i64").code == 4


def test_unknown_command_and_option_are_usage_errors(icli):
    assert icli("frobnicate", "sample.o").code == 2
    assert icli("list", "functions", "--frobnicate", "sample.o").code == 2
    assert icli("list", "nonsense", "sample.o").code == 2


def test_malformed_selector_fails_before_loading(icli):
    r = icli("resolve", "sample.o", "func:*[size >]")
    assert r.code == 2 and "loading" not in r.err


def test_bare_decimal_address_rejected(icli):
    assert icli("resolve", "sample.o", "4198400").code == 2


def test_resolve_names_ranges_and_graph_operators(icli):
    r = icli("resolve", "sample.o", "callers*(imp:*!recv)")
    names = {x["name"] for x in r.records}
    assert names == {"net_dispatch", "main"}, names
    r = icli("resolve", "sample.o", "callers(imp:*!memcpy) & func:*[size > 0x40]")
    assert [x["name"] for x in r.records] == ["parse_packet"]
    r = icli("resolve", "sample.o", "func:* ~ func:*[size > 0x10]")
    assert all(x["name"] != "parse_packet" for x in r.records)


def test_resolve_unknown_name_is_status_5(icli):
    assert icli("resolve", "sample.o", "definitely_not_here").code == 5


def test_resolve_empty_predicate_result_is_status_1(icli):
    r = icli("resolve", "sample.o", "func:*[size > 0x100000]")
    assert r.code == 1 and r.out == ""


def test_list_where_sort_limit_and_fields(icli):
    r = icli("list", "functions", "sample.o", "--where", "!thunk && size > 8", "--sort", "size:desc", "-n", "2",
             "--fields", "name,size")
    assert r.code == 0
    recs = r.records
    assert len(recs) == 2 and recs[0]["size"] >= recs[1]["size"]
    assert set(recs[0]) == {"_t", "name", "size"}


def test_list_where_matching_nothing_is_status_1(icli):
    r = icli("list", "functions", "sample.o", "--where", "size > 0x7fffffff")
    assert r.code == 1


def test_list_count_and_template(icli):
    r = icli("list", "functions", "--count", "sample.o")
    assert r.code == 0 and r.record["count"] >= 10
    r = icli("list", "functions", "sample.o", "--match", "parse_*", "-t", "{name}|{size:#x}|{callees}")
    assert r.out.strip() == "parse_packet|0x70|3"


def test_template_header_footer_and_null(icli):
    r = icli("list", "segments", "sample.o", "-t", "{name}", "--header", "BEGIN\\n", "--footer", "END {count}\\n")
    lines = r.out.splitlines()
    assert lines[0] == "BEGIN" and lines[-1].startswith("END ")
    r = icli("-0", "list", "functions", "sample.o", "-t", "{name}")
    assert "\0" in r.out and "\n" not in r.out


def test_csv_and_json_formats(icli):
    r = icli("-f", "csv", "list", "imports", "sample.o")
    lines = r.out.splitlines()
    assert lines[0].startswith("ea,") and any("recv" in x for x in lines[1:])
    r = icli("-f", "json", "list", "imports", "sample.o")
    doc = json.loads(r.out)
    assert doc["schema"] == "icli.import/1" and isinstance(doc["records"], list)


def test_addr_styles(icli):
    for style, prefix in (("seg", ".text:"), ("rva", "rva:0x"), ("bare", "")):
        r = icli("--addr", style, "resolve", "sample.o", "main")
        assert r.record["ea"].startswith(prefix), (style, r.record)
    r = icli("--addr", "seg", "resolve", "sample.o", ".text:0000000000000180")
    assert r.record["name"] == "main"


def test_xrefs_pipe_into_decompile_at_line(icli):
    x = icli("xrefs", "--type", "call", "sample.o", "imp:*!system")
    assert x.code == 0 and len(x.records) == 2
    d = icli("decompile", "--at-line", "sample.o", "-", stdin=x.out)
    texts = [r["text"] for r in d.records]
    assert all("system(" in t for t in texts), texts


def test_xrefs_bad_type_is_usage(icli):
    assert icli("xrefs", "--type", "bogus", "sample.o", "main").code == 2


def test_decompile_requires_selector_or_all(icli):
    assert icli("decompile", "sample.o").code == 2


def test_decompile_all_and_with_types(icli):
    r = icli("decompile", "--all", "sample.o")
    assert r.code == 0, r.out[-500:]
    names = {x["name"] for x in r.records}
    assert names >= {"main", "parse_packet", "handle_kind"} and "recv" not in names



def test_unwritable_cache_dir_is_reported_as_such(icli):
    r = icli("info", "sample.o", env={"ICLI_CACHE_DIR": "/nonexistent/icli-cache"})
    assert r.code == 4 and "cache directory" in r.err


def test_disasm_whole_function_and_bytes(icli):
    r = icli("-f", "raw", "disasm", "--bytes", "sample.o", "substitute")
    assert r.code == 0
    assert "retn" in r.out and "C3" in r.out
    r = icli("disasm", "sample.o", "substitute")
    assert [x["mnem"] for x in r.records] == ["mov", "movzx", "retn"]


def test_disasm_graph_dot(icli):
    r = icli("disasm", "--graph", "dot", "sample.o", "handle_kind")
    assert r.code == 0 and r.out.startswith("digraph")


def test_callgraph_records_and_depth(icli):
    r = icli("callgraph", "--callees", "--depth", "1", "sample.o", "net_dispatch")
    assert {x["callee"] for x in r.records} == {"recv", "parse_packet"}
    r = icli("callgraph", "--callers", "sample.o", "substitute")
    assert {x["caller"] for x in r.records} >= {"handle_kind", "parse_packet"}
    assert icli("callgraph", "--depth", "0", "sample.o", "main").code == 2


def test_search_modes(icli):
    r = icli("search", "--crypto", "sample.o")
    assert any(x["name"] == "AES_sbox" for x in r.records)
    r = icli("search", "--string", "^https?://", "sample.o")
    assert {x["value"] for x in r.records} == {"https://updates.example.com/check", "http://backup.example.net/v1"}
    r = icli("search", "--bytes", "63 7c 77 7b", "sample.o")
    assert r.code == 0 and len(r.records) == 1
    r = icli("search", "--insn", "call*system*", "sample.o")
    assert len(r.records) == 2
    assert icli("search", "--bytes", "zz", "sample.o").code == 2
    assert icli("search", "--string", "no-such-string-anywhere", "sample.o").code == 1


def test_search_requires_exactly_one_mode(icli):
    assert icli("search", "sample.o").code == 2
    assert icli("search", "--crypto", "--imm", "1", "sample.o").code == 2


def test_list_every_kind(icli):
    kinds = ["functions", "names", "strings", "imports", "exports", "entries", "segments", "xrefs", "types",
             "tils", "sigs", "comments", "bookmarks", "tags", "problems", "fixups", "blocks", "patches", "switches"]
    for k in kinds:
        r = icli("list", k, "sample.o", "-n", "3")
        assert r.code in (0,), (k, r.err)
    r = icli("list", "lvars", "sample.o", "parse_packet")
    assert any(x["arg"] for x in r.records)
    r = icli("list", "switches", "sample.o")
    assert r.record["ncases"] == 7


def test_show_function(icli):
    r = icli("show", "sample.o", "main")
    rec = r.record
    assert rec["func"] == "main" and rec["function"]["callees"]


def test_status_and_info(icli):
    r = icli("status", "sample.o")
    assert r.code == 0 and r.record["state"] in ("analyzed", "enriched")
    r = icli("info", "sample.o")
    info = r.record
    assert info["processor"] == "metapc" and info["bitness"] == 64 and info["cache_key"]


def test_default_target_from_env(icli, workdir):
    r = icli("list", "functions", "--count", env={"ICLI_DB": str(workdir / "sample.o")})
    # ICLI_DB names an input file here; the first positional is a selector-less command
    assert r.code == 0 and r.record["count"] > 0


def test_show_code_prints_python(icli):
    r = icli("--show-code", "list", "functions", "--where", "size > 0x40", "sample.o")
    assert r.code == 0 and "db.functions" in r.out and "f.size() > 64" in r.out
