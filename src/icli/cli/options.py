"""Global options and load options (GLOBAL OPTIONS / LOAD OPTIONS in idx(1)).

Global options may appear before the command name and, for convenience,
anywhere after it; the same definitions are added to every parser with
``SUPPRESS`` defaults so a later occurrence never resets an earlier one.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from typing import Any

from ..errors import usage
from ..lang.values import parse_duration, parse_int
from .output import FORMATS, OutputOptions

S = argparse.SUPPRESS


def _append(p: argparse.ArgumentParser, *names: str, **kw: Any) -> None:
    p.add_argument(*names, action="append", default=S, **kw)


def add_global_options(p: argparse.ArgumentParser, skip: frozenset[str] = frozenset()) -> None:
    """``skip``: option strings a command redefines (``tag --color RRGGBB``)."""
    group = p.add_argument_group("global options")

    class _G:
        @staticmethod
        def add_argument(*names: str, **kw: Any) -> None:
            if not skip.intersection(names):
                group.add_argument(*names, **kw)

    g = _G()
    g.add_argument("--db", metavar="PATH", default=S, help="use or create the database at PATH")
    g.add_argument("--no-cache", action="store_true", default=S, help="analyse into a temporary database")
    g.add_argument("--read-only", action="store_true", default=S, help="open read-only; edits exit 13")
    g.add_argument("--analysis", choices=("auto", "none", "wait"), default=S)
    g.add_argument("--analysis-timeout", metavar="DURATION", default=S)
    g.add_argument("-f", "--format", choices=FORMATS, default=S)
    g.add_argument("-t", "--template", metavar="TMPL", default=S)
    g.add_argument("--header", metavar="TMPL", default=S, help="template rendered before the records")
    g.add_argument("--footer", metavar="TMPL", default=S, help="template rendered after the records")
    g.add_argument("--fields", metavar="LIST", default=S)
    g.add_argument("--schema-version", type=int, metavar="N", default=S)
    g.add_argument("--no-header", action="store_true", default=S)
    g.add_argument("-0", "--null", action="store_true", default=S)
    g.add_argument("--addr", choices=("hex", "bare", "seg", "rva", "file"), default=S)
    g.add_argument("--color", choices=("auto", "always", "never"), default=S)
    g.add_argument("-q", "--quiet", action="store_true", default=S)
    g.add_argument("-v", "--verbose", action="count", default=S)
    g.add_argument("--log", metavar="FILE", default=S)
    g.add_argument("--set", metavar="KEY=VALUE", action="append", default=S)
    g.add_argument("--plugin-opt", metavar="NAME:OPTION", action="append", default=S)
    g.add_argument("-j", "--jobs", type=int, metavar="N", default=S)
    g.add_argument("-C", dest="chdir", metavar="DIR", default=S)
    g.add_argument("--no-server", action="store_true", default=S)
    g.add_argument("--no-plugins", action="store_true", default=S)
    g.add_argument("--dry-run", action="store_true", default=S)
    g.add_argument("--strict", action="store_true", default=S)
    g.add_argument("--allow-execute", action="store_true", default=S)
    g.add_argument("--show-code", action="store_true", default=S)
    g.add_argument("--demangle", dest="demangle", action="store_true", default=S)
    g.add_argument("--no-demangle", dest="demangle", action="store_false", default=S)


def add_load_options(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("load options")
    g.add_argument("--loader", metavar="NAME", default=S)
    g.add_argument("--processor", metavar="NAME[:VARIANT]", default=S)
    g.add_argument("--bitness", type=int, choices=(16, 32, 64), default=S)
    g.add_argument("--endian", choices=("little", "big"), default=S)
    g.add_argument("--base", metavar="ADDR", default=S)
    g.add_argument("--entry", metavar="ADDR", default=S)
    g.add_argument("--compiler", metavar="ID[:ABI]", default=S)
    _append(g, "--segment", metavar="NAME=START-END[:CLASS][:PERM][@FILE[:OFFSET]]")
    g.add_argument("--svd", metavar="FILE", default=S)
    _append(g, "--load-opt", metavar="LOADER.KEY=VALUE")
    g.add_argument("--symbols", metavar="SRC[,SRC...]", default=S)
    g.add_argument("--encoding", metavar="NAME", default=S)
    g.add_argument("--no-segmentation", action="store_true", default=S)
    g.add_argument("--pack", choices=("compress", "pack", "none"), default=S)


GLOBAL_DESTS = {
    "db", "no_cache", "read_only", "analysis", "analysis_timeout", "format", "template", "header", "footer",
    "fields", "schema_version", "no_header", "null", "addr", "color", "quiet", "verbose", "log", "set",
    "plugin_opt", "jobs", "chdir", "no_server", "no_plugins", "dry_run", "strict", "allow_execute",
    "show_code", "demangle",
}
LOAD_DESTS = {"loader", "processor", "bitness", "endian", "base", "entry", "compiler", "segment", "svd",
              "load_opt", "symbols", "encoding", "no_segmentation", "pack"}


@dataclass
class GlobalOptions:
    db: str | None = None
    no_cache: bool = False
    read_only: bool = False
    analysis: str = "auto"
    analysis_timeout: float | None = None
    output: OutputOptions = field(default_factory=OutputOptions)
    schema_version: int | None = None
    addr: str = "hex"
    log: str | None = None
    set: list[str] = field(default_factory=list)
    plugin_opt: list[str] = field(default_factory=list)
    jobs: int = 0
    no_server: bool = False
    no_plugins: bool = False
    dry_run: bool = False
    strict: bool = False
    allow_execute: bool = False
    show_code: bool = False
    demangle: bool | None = None
    load: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "GlobalOptions":
        from .config import CONFIG
        from .env import env

        d = vars(ns)
        defaults = CONFIG.get("defaults") or {}

        def pick(name: str, fallback: Any = None, env_name: str | None = None) -> Any:
            if name in d:
                return d[name]
            if env_name and env(env_name) is not None:
                return env(env_name)
            return defaults.get(name, defaults.get(name.replace("_", "-"), fallback))

        g = cls()
        g.db = pick("db")
        g.no_cache = bool(pick("no_cache", False))
        g.read_only = bool(pick("read_only", False))
        g.analysis = pick("analysis", "auto")
        if g.analysis not in ("auto", "none", "wait"):
            raise usage(f"--analysis must be auto, none or wait (not {g.analysis!r})")
        t = pick("analysis_timeout")
        g.analysis_timeout = parse_duration(t) if t not in (None, "") else None
        fmt = pick("format", None, "FORMAT")
        if fmt is not None and fmt not in FORMATS:
            raise usage(f"unknown format {fmt!r}; one of {', '.join(FORMATS)}")
        fields_ = pick("fields")
        g.output = OutputOptions(
            format=fmt,
            template=pick("template"),
            header=pick("header"),
            footer=pick("footer"),
            fields=[f.strip() for f in fields_.split(",") if f.strip()] if isinstance(fields_, str) else
            (list(fields_) if fields_ else None),
            no_header=bool(pick("no_header", False)),
            null=bool(pick("null", False)),
            color=pick("color", "auto"),
            quiet=bool(pick("quiet", False)),
            verbose=int(pick("verbose", 0) or 0),
        )
        g.schema_version = pick("schema_version")
        g.addr = pick("addr", "hex")
        g.log = pick("log") or os.environ.get("IDALOG")
        g.set = list(d.get("set") or [])
        g.plugin_opt = list(d.get("plugin_opt") or [])
        jobs = pick("jobs", None, "JOBS")
        g.jobs = int(jobs) if jobs else (os.cpu_count() or 1)
        g.no_server = bool(pick("no_server", False)) or env("NO_SERVER") == "1"
        g.no_plugins = bool(pick("no_plugins", False))
        g.dry_run = bool(pick("dry_run", False))
        g.strict = bool(pick("strict", False))
        g.allow_execute = bool(pick("allow_execute", False)) or env("ALLOW_EXECUTE") == "1"
        g.show_code = bool(pick("show_code", False))
        g.demangle = d.get("demangle")
        g.load = load_options(d)
        return g


def load_options(d: dict[str, Any]) -> dict[str, Any]:
    """Normalised load options (part of the cache key)."""
    from .config import CONFIG

    conf = CONFIG.get("load") or {}
    out: dict[str, Any] = {}
    for name in sorted(LOAD_DESTS):
        v = d.get(name)
        if v is None and name in conf:
            v = conf[name]
        if v in (None, False, [], ""):
            continue
        if name in ("base", "entry"):
            v = parse_int(v)
        if name == "symbols" and isinstance(v, str):
            v = [s.strip() for s in v.split(",") if s.strip()]
        if name == "symbols" and v == ["auto"]:
            continue
        if name in ("svd",):
            v = os.path.abspath(v)
        if name == "segment":
            v = [_abs_segment(s) for s in v]
        out[name] = v
    return out


def _abs_segment(spec: str) -> str:
    head, at, tail = spec.partition("@")
    if not at:
        return spec
    path, colon, off = tail.rpartition(":") if tail.count(":") and not os.path.exists(tail) else (tail, "", "")
    return f"{head}@{os.path.abspath(path)}{colon}{off}"
