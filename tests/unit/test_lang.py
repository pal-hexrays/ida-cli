"""Adversarial tests for the pure-Python language layer (no IDA needed)."""

import pytest

from icli.errors import Exit, IdaxError, combine
from icli.lang import expr, selector, template, values


# -- values -----------------------------------------------------------------

@pytest.mark.parametrize("text,want", [
    ("0x401000", 0x401000), ("401000h", 0x401000), ("0x8000_1234", 0x80001234),
    ("0d4198400", 4198400), ("0FFh", 0xFF), ("0b101", 5),
])
def test_address_literals(text, want):
    assert values.parse_address_number(text) == want


@pytest.mark.parametrize("text", ["401000", "main", "0x", "h", "FFh", "0xZZ", "", "1.5"])
def test_address_literal_rejects(text):
    # bare decimals are ambiguous; FFh does not start with a digit (IDA rule)
    assert values.parse_address_number(text) is None


@pytest.mark.parametrize("text,want", [("90s", 90), ("15m", 900), ("2h", 7200),
                                       ("1h30m", 5400), ("7d", 604800), ("250ms", 0.25), ("10", 10)])
def test_durations(text, want):
    assert values.parse_duration(text) == pytest.approx(want)


@pytest.mark.parametrize("text", ["", "abc", "10x", "m5", "-5s"])
def test_duration_rejects(text):
    with pytest.raises(IdaxError) as e:
        values.parse_duration(text)
    assert e.value.status == Exit.USAGE


def test_sizes():
    assert values.parse_size("50G") == 50 << 30
    assert values.parse_size("512M") == 512 << 20
    with pytest.raises(IdaxError):
        values.parse_size("lots")


# -- exit status combination -----------------------------------------------------

def test_combine_lowest_nonzero_wins_but_partial_yields():
    assert combine(0, 0) == 0
    assert combine(0, 5) == 5
    assert combine(9, 5) == 5
    assert combine(3, 1) == 1          # 3 yields to any hard error
    assert combine(3, 16) == 16
    assert combine(3, 0) == 3
    assert combine(1, 3) == 1


# -- templates --------------------------------------------------------------------

def test_template_specs_and_escapes():
    t = template.parse(r"{ea}\t{size:>8}\t{name:<6.6}|{hash:.4}\c")
    out = t.render({"ea": "0x401000", "size": 16, "name": "very_long_name", "hash": "deadbeef"})
    assert out == "0x401000\t      16\tvery_l|dead"


def test_template_hex_spec_on_address_string():
    # addresses travel as strings; numeric specs must still work on them
    assert template.render_inline("{ea:#x} {size:#x}", {"ea": "0x10", "size": 255}) == "0x10 0xff"


def test_template_lists_dicts_missing_and_braces():
    rec = {"tags": ["a", "b"], "obj": {"k": 1}}
    assert template.render_inline("{tags:,}", rec) == "a,b"
    assert template.render_inline("{tags: | }", rec) == "a | b"
    assert template.render_inline("{tags}", rec) == "a,b"
    assert template.render_inline("{obj}", rec) == '{"k":1}'
    assert template.render_inline("[{missing}]", rec) == "[]"
    assert template.render_inline("{{literal}}", rec) == "{literal}"
    assert template.render_inline("{obj.k}", rec) == "1"


def test_template_default_newline():
    assert template.parse("{a}").render({"a": 1}) == "1\n"


@pytest.mark.parametrize("bad", ["{unterminated", "oops}", "{1abc}", "{a b}", "{}"])
def test_template_rejects(bad):
    with pytest.raises(IdaxError) as e:
        template.parse(bad)
    assert e.value.status == Exit.USAGE


def test_template_bad_spec_is_usage_error():
    with pytest.raises(IdaxError):
        template.render_inline("{name:#x}", {"name": "main"})


def test_template_fields_listing():
    assert template.parse("{b} {a} {b:>3}").fields == ["b", "a"]


def test_path_template_sanitizes_values_not_separators():
    path = template.render_path("src/{name}.c", {"name": "std::vector<int>::push/back"})
    assert path.startswith("src/")
    assert "/" not in path[4:] and ":" not in path and "<" not in path


# -- predicates -------------------------------------------------------------------

def _rec(**kw):
    return lambda name: kw.get(name)


@pytest.mark.parametrize("text,rec,want", [
    ("size > 0x400 && !lib", dict(size=0x500, lib=False), True),
    ("size > 0x400 && !lib", dict(size=0x500, lib=True), False),
    ("size > 0x400 && !lib", dict(size=None, lib=False), False),   # missing field
    ('module ~ "(?i)ws2_32"', dict(module="WS2_32.dll"), True),
    ('module ~ "(?i)ws2_32"', dict(module=None), False),
    ("ea >= 0x401000", dict(ea="0x401000"), True),                 # address strings
    ("hexrays_err != 0", dict(hexrays_err=None), True),
    ("a || b && c", dict(a=False, b=True, c=False), False),          # && binds tighter
    ("!(a || b)", dict(a=False, b=False), True),
    ("size - 4 == 12", dict(size=16), True),
    ("name == 'main'", dict(name="main"), True),
    ("tags == 'crypto'", dict(tags=["x", "crypto"]), True),       # membership
    ("dummy", dict(dummy=True), True),
    ("1 / 0 == 0", {}, False),                                     # no ZeroDivisionError
])
def test_predicates(text, rec, want):
    assert expr.test(text, _rec(**rec)) is want


@pytest.mark.parametrize("bad", ["", "size >", "&& a", "(a", "a b", "size > 0x", "'unterminated", "a ~ "])
def test_predicate_rejects(bad):
    with pytest.raises(IdaxError) as e:
        expr.parse(bad)
    assert e.value.status == Exit.USAGE


def test_predicate_bad_regex_is_usage():
    with pytest.raises(IdaxError):
        expr.test('name ~ "("', _rec(name="x"))


def test_predicate_fields():
    assert expr.fields(expr.parse("size > 1 && (lib || name ~ 'x')")) == ["size", "lib", "name"]


# -- selectors --------------------------------------------------------------------

def test_selector_atoms():
    assert selector.parse("0x401000") == {"op": "addr", "expr": {"terms": [["+", {"num": 0x401000}]]}}
    n = selector.parse("main+0x2c")
    assert n["expr"]["terms"] == [["+", {"name": "main"}], ["+", {"num": 0x2C}]]
    n = selector.parse("$entry-4")
    assert n["expr"]["terms"] == [["+", {"sym": "entry"}], ["-", {"num": 4}]]
    assert selector.parse(".text:401000")["expr"]["terms"][0][1] == {"seg": ".text", "num": 0x401000}
    assert selector.parse("rva:0x1000")["expr"]["terms"][0][1] == {"rva": 0x1000}
    assert selector.parse('"CView::OnPaint"')["expr"]["terms"][0][1] == {"name": "CView::OnPaint", "demangled": True}
    mangled = "?OnPaint@CView@@MAEXPAVCDC@@@Z"
    assert selector.parse(mangled)["expr"]["terms"][0][1] == {"name": mangled}


def test_selector_bare_decimal_rejected():
    with pytest.raises(IdaxError) as e:
        selector.parse("401000")
    assert e.value.status == Exit.USAGE


def test_selector_ranges():
    r = selector.parse("0x1000..0x2000")
    assert r["op"] == "range" and r["end"]["terms"][0][1] == {"num": 0x2000}
    r = selector.parse("0x1000+0x100")
    assert r["op"] == "range" and r["size"]["terms"][0][1] == {"num": 0x100}
    r = selector.parse("main..")
    assert r["op"] == "range" and r["end"] is None


def test_selector_typed_and_regex():
    n = selector.parse("func:/^ssl_/i")
    assert n == {"op": "typed", "type": "func", "pattern": "^ssl_", "regex": True, "flags": "i"}
    n = selector.parse("imp:kernel32!Create*")
    assert n["module"] == "kernel32" and n["pattern"] == "Create*"
    n = selector.parse("imp:recv")
    assert n["module"] == "*" and n["pattern"] == "recv"
    assert selector.parse("func@0x401000")["op"] == "func_at"
    assert selector.parse("lib")["op"] == "class"


def test_selector_bytes_pattern():
    assert selector.parse("bytes:558BEC??")["pattern"] == "558BEC??"
    with pytest.raises(IdaxError):
        selector.parse("bytes:5G")


def test_selector_set_operators_and_precedence():
    n = selector.parse("a | b & c ~ d")
    # union lowest; & binds tighter than ~
    assert n["op"] == "union"
    assert n["args"][1]["op"] == "diff"
    assert n["args"][1]["args"][0]["op"] == "inter"
    assert selector.parse("!lib")["op"] == "not"
    assert selector.parse("(a, b)")["op"] == "union"


def test_selector_graph_ops():
    n = selector.parse("callers(imp:*!VirtualProtect, 3)[!lib]")
    assert n["op"] == "pred" and n["expr"] == "!lib"
    g = n["arg"]
    assert g["name"] == "callers" and g["depth"] == 3 and not g["closure"]
    assert g["arg"]["module"] == "*" and g["arg"]["pattern"] == "VirtualProtect"
    n = selector.parse("callers*(imp:*!recv) & callers(imp:*!memcpy)")
    assert n["op"] == "inter" and n["args"][0]["closure"] is True
    assert selector.parse("uses_type(pkt_t)")["pattern"] == "pkt_t"
    # a function literally named "callers" is still an address atom
    assert selector.parse("callers")["op"] == "addr"


def test_selector_predicates_chain():
    n = selector.parse("func:*[size > 0x400][xrefs_to >= 10]")
    assert n["op"] == "pred" and n["arg"]["op"] == "pred"
    n = selector.parse('str:*http*[xrefs_to == 0]')
    assert n["arg"]["pattern"] == "*http*"
    n = selector.parse('func:*[name ~ "a]b"]')  # quotes protect brackets
    assert n["expr"] == 'name ~ "a]b"'


def test_selector_special_atoms():
    assert selector.parse("%") == {"op": "prev"}
    assert selector.parse("-") == {"op": "stdin"}
    assert selector.parse("@list.txt") == {"op": "file", "path": "list.txt"}


@pytest.mark.parametrize("bad", ["", "(", "a &", "func:*[", "func:*[size >]", "callers(a, x)",
                                 "callers(a, 0)", "$nope", "rva:12", "func:/(/", "a)", "[x]",
                                 "func:/x/q"])
def test_selector_rejects(bad):
    with pytest.raises(IdaxError) as e:
        selector.parse(bad)
    assert e.value.status == Exit.USAGE
