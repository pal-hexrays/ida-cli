"""Shared fixtures.  End-to-end tests (marked ``ida``) run the real CLI
against real idalib workers; they need a configured IDA installation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def records(self) -> list[dict]:
        return [json.loads(line) for line in self.out.splitlines() if line.strip()]

    @property
    def record(self) -> dict:
        recs = self.records
        assert len(recs) == 1, f"expected one record, got {len(recs)}: {self.out[:500]}"
        return recs[0]


@pytest.fixture(scope="session")
def cache_dir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("icli-cache")


@pytest.fixture(scope="session")
def workdir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("work")
    for name in ("sample.o", "crackme03.elf"):
        shutil.copy(FIXTURES / name, d / name)
    return d


@pytest.fixture(scope="session")
def icli(cache_dir, workdir):
    """Run ``icli`` (``-f jsonl`` unless a format is given) in the work dir."""

    def run(*args: str, stdin: str | None = None, env: dict | None = None, cwd: Path | None = None,
            timeout: float = 600) -> Result:
        e = dict(os.environ)
        e["ICLI_CACHE_DIR"] = str(cache_dir)
        e.pop("ICLI_DB", None)
        e.update(env or {})
        proc = subprocess.run([sys.executable, "-m", "icli", *args], input=stdin, capture_output=True,
                              text=True, cwd=cwd or workdir, env=e, timeout=timeout)
        return Result(proc.returncode, proc.stdout, proc.stderr)

    return run


@pytest.fixture
def fresh(tmp_path):
    """A private copy of the sample object, so edit tests do not interfere."""
    p = tmp_path / "sample.o"
    shutil.copy(FIXTURES / "sample.o", p)
    return p
