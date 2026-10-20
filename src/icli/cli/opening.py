"""Open a session for a target given the global options."""

from __future__ import annotations

from typing import Callable

from . import cache, loading, settings
from .config import CONFIG
from .options import GlobalOptions
from .session import Session, SessionOptions
from .target import Target, resolve


def resolve_target(spec: str, g: GlobalOptions) -> Target:
    return resolve(spec, g.load, db=g.db, no_cache=g.no_cache)


def session_options(g: GlobalOptions) -> SessionOptions:
    return SessionOptions(
        analysis=g.analysis,
        analysis_timeout=g.analysis_timeout,
        read_only=g.read_only,
        no_server=g.no_server,
        verbose=g.output.verbose,
        quiet=g.output.quiet,
    )


def open_session(spec: str | None, g: GlobalOptions, diag: Callable[[str, str, str], None]) -> Session:
    from ..errors import usage

    if spec is None:
        raise usage("no target given")
    target = resolve_target(spec, g)
    st = settings.parse(g.set, {"ida": CONFIG.get("ida"), "hexrays": CONFIG.get("hexrays")})
    load_spec = loading.build(g.load, st, g.plugin_opt, g.log)
    session = Session(target, load_spec, session_options(g), diag)
    session.open()
    if st.hexrays:
        session.call("settings.hexrays", {"directives": st.hexrays}, need="loaded")
    cache.remember_last(target.spec if not target.spec.startswith("@") else str(target.db))
    return session
