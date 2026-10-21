"""Running as a single-file binary (PyInstaller).

A binary has no Python installation next to it, so the ida-nexus worker
cannot be started as the ``ida-nexus`` console script: the binary starts
itself instead, as ``<binary> worker ...``, with a marker in the
environment, and :func:`setup` hands that process to ida-nexus.
"""

from __future__ import annotations

import os
import sys

FROZEN = bool(getattr(sys, "frozen", False))
_WORKER_MARKER = "ICLI_NEXUS_WORKER"


def self_command() -> list[str]:
    """The command line that runs icli again."""
    return [sys.executable] if FROZEN else [sys.executable, "-m", "icli"]


def setup() -> None:
    """Run before anything else when icli starts."""
    if not FROZEN:
        return
    if sys.argv[1:2] == ["worker"] and os.environ.get(_WORKER_MARKER) == "1":
        from ida_nexus.cli import main

        sys.exit(main(sys.argv[1:]))
    import ida_nexus._resolver as resolver

    os.environ[_WORKER_MARKER] = "1"
    resolver._find_console_script = lambda name: sys.executable
