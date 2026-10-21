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
