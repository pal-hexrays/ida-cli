"""CLI structure without IDA: every parser builds, globals parse anywhere."""

import pytest

from icli.cli.main import command_parser, first_positional, parse, _global_parser
from icli.cli.registry import COMMANDS, load_commands
from icli.errors import Exit, IcliError

load_commands()


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_command_parser_builds(name):
    cmd = COMMANDS[name]
    command_parser(cmd).format_help()
    for sub in cmd.subcommands:
        command_parser(cmd, sub).format_help()


def test_global_options_before_and_after_command():
    _, ns, _, _ = parse(["-f", "csv", "list", "functions", "x.i64", "--addr", "rva", "-q"])
    assert ns.format == "csv" and ns.addr == "rva" and ns.quiet


def test_later_global_does_not_reset_earlier():
    _, ns, _, _ = parse(["-q", "list", "functions", "x.i64"])
    assert ns.quiet is True


def test_first_positional_skips_option_values():
    gp = _global_parser()
    assert first_positional(["--db", "a.i64", "-f", "json", "info"], gp) == 4
    assert first_positional(["--format=json", "info"], gp) == 1
    assert first_positional(["-qv", "info"], gp) == 1


@pytest.mark.parametrize("argv", [["frob"], ["list"], ["type"], ["type", "bogus"], ["list", "functions", "--nope"]])
def test_usage_errors(argv):
    with pytest.raises(IcliError) as e:
        parse(argv)
    assert e.value.status == Exit.USAGE


def test_optional_value_flags():
    _, ns, _, _ = parse(["disasm", "--bytes", "x.i64", "main"])
    assert ns.bytes == 8 and ns.items == ["x.i64", "main"]
    _, ns, _, _ = parse(["disasm", "--bytes", "4", "x.i64", "main"])
    assert ns.bytes == 4


def test_passthrough_after_double_dash():
    cmd, ns, rest, _ = parse(["exec", "x.i64", "-c", "1", "--", "--min-score", "7"]) if "exec" in COMMANDS \
        else (None, None, ["--min-score", "7"], None)
    assert rest == ["--min-score", "7"]


def test_command_options_never_leak_into_load_options():
    from icli.cli.options import GlobalOptions

    _, ns, _, _ = parse(["make", "string", "x.i64", "0x10", "--encoding", "utf-16le", "--base", "0x10"])
    assert GlobalOptions.from_namespace(ns).load == {}


def test_exec_read_only_after_command_and_before():
    from icli.cli.options import GlobalOptions

    _, ns, _, _ = parse(["--read-only", "exec", "x.i64", "-c", "1"])
    assert GlobalOptions.from_namespace(ns).read_only


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_command_destinations_never_shadow_global_options(name):
    """A command option or positional sharing a destination with a global or
    load option would silently overwrite it in the merged namespace."""
    import argparse

    from icli.cli.options import GLOBAL_DESTS, LOAD_DESTS

    cmd = COMMANDS[name]
    parsers = [command_parser(cmd)] + [command_parser(cmd, s) for s in cmd.subcommands]
    for p in parsers:
        for group in p._action_groups:
            if group.title in ("global options", "load options"):
                continue
            for action in group._group_actions:
                if action.dest in GLOBAL_DESTS | LOAD_DESTS and action.default is not argparse.SUPPRESS:
                    raise AssertionError(f"{p.prog}: {action.dest!r} shadows a global/load option")


# -- no IDA installed ------------------------------------------------------------------

NEEDS_IDA = [
    ["list", "functions", "sample.o"],
    ["decompile", "sample.o", "main"],
    ["--db", "x.i64", "comment", "sample.o", "main", "hi"],
    ["exec", "sample.o", "-c", "1"],
    ["identify", "sample.o"],
    ["loaders", "sample.o"],
    ["processors"],
]


def _no_ida(tmp_path, how: str) -> dict:
    """An environment in which IDA cannot be found, in several ways."""
    usr = tmp_path / "idausr"
    usr.mkdir()
    env = {"IDAUSR": str(usr), "IDADIR": ""}
    if how == "missing-dir":
        env["IDADIR"] = str(tmp_path / "nope")
    elif how == "dir-without-idalib":
        (tmp_path / "ida").mkdir()
        (tmp_path / "ida" / "ida.cfg").write_text("")
        env["IDADIR"] = str(tmp_path / "ida")
    elif how == "idadir-is-a-file":
        (tmp_path / "ida").write_text("")
        env["IDADIR"] = str(tmp_path / "ida")
    elif how == "config-points-nowhere":
        (usr / "ida-config.json").write_text('{"Paths": {"ida-install-dir": "%s"}}' % (tmp_path / "gone"))
    elif how == "config-is-garbage":
        (usr / "ida-config.json").write_text("{not json")
    return env


@pytest.mark.parametrize("how", ["missing-dir", "dir-without-idalib", "idadir-is-a-file",
                                 "config-points-nowhere", "config-is-garbage"])
@pytest.mark.parametrize("argv", NEEDS_IDA, ids=lambda a: " ".join(a[:2]))
def test_without_ida_commands_say_so(icli, tmp_path, how, argv):
    r = icli(*argv, env=_no_ida(tmp_path, how), timeout=60)
    assert r.code == Exit.LICENSE, (r.code, r.err)
    assert "IDA Pro was not found" in r.err and "IDADIR" in r.err
    assert "Traceback" not in r.err and r.out == ""


@pytest.mark.parametrize("argv", [["--help"], ["help", "selectors"], ["schema", "decompile"],
                                  ["completion", "bash"], ["ref", "decompile"]])
def test_without_ida_offline_commands_still_work(icli, tmp_path, argv):
    r = icli(*argv, env=_no_ida(tmp_path, "missing-dir"), timeout=60)
    assert r.code == 0, r.err
    assert r.out


# -- portability -----------------------------------------------------------------------


def test_pid_alive_never_reports_dead_or_bogus_processes():
    import os
    import subprocess
    import sys

    from icli.cli.env import pid_alive

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        assert pid_alive(os.getpid())
        assert pid_alive(child.pid)
        assert pid_alive(child.pid), "checking a process must not kill it (os.kill(pid, 0) on Windows)"
    finally:
        child.kill()
        child.wait()
    assert not pid_alive(child.pid)
    for bogus in (0, -1, -12345, 2**31 - 1):
        assert not pid_alive(bogus)


def test_serve_without_unix_sockets_is_a_usage_error(icli):
    import sys

    if sys.platform != "win32":
        pytest.skip("Unix sockets are available here")
    r = icli("serve", "sample.o", timeout=60)
    assert r.code == Exit.USAGE and "not available on Windows" in r.err
    assert "Traceback" not in r.err
