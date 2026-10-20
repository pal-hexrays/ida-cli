"""The database cache: ``$ICLI_CACHE_DIR/xx/key.i64`` plus an SQLite index."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from .env import cache_dir, kernel_version

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    key TEXT PRIMARY KEY,
    input TEXT,
    sha256 TEXT,
    load TEXT,
    kernel TEXT,
    db TEXT,
    state TEXT,
    created REAL,
    accessed REAL
);
CREATE TABLE IF NOT EXISTS hashes (
    path TEXT PRIMARY KEY,
    size INTEGER,
    mtime_ns INTEGER,
    sha256 TEXT
);
CREATE TABLE IF NOT EXISTS handles (
    name TEXT PRIMARY KEY,
    target TEXT,
    created REAL
);
"""


def index_path() -> Path:
    return cache_dir() / "index.sqlite"


def connect() -> sqlite3.Connection:
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(index_path(), timeout=30)
    conn.executescript(SCHEMA)
    return conn


def file_sha256(path: Path) -> str:
    """SHA-256 of a file, memoised in the index by (path, size, mtime)."""
    st = path.stat()
    key = str(path.resolve())
    try:
        with connect() as conn:
            row = conn.execute("SELECT size, mtime_ns, sha256 FROM hashes WHERE path=?", (key,)).fetchone()
            if row and row[0] == st.st_size and row[1] == st.st_mtime_ns:
                return row[2]
    except sqlite3.Error:
        row = None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    try:
        with connect() as conn:
            conn.execute("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?)",
                         (key, st.st_size, st.st_mtime_ns, digest))
    except sqlite3.Error:
        pass
    return digest


def cache_key(sha256: str, load: dict[str, Any]) -> str:
    material = json.dumps({"sha256": sha256, "load": load, "kernel": kernel_version()}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def db_path_for(key: str) -> Path:
    return cache_dir() / key[:2] / f"{key}.i64"


def record(key: str, input_path: Path, sha256: str, load: dict, db: Path) -> None:
    now = time.time()
    try:
        with connect() as conn:
            conn.execute(
                "INSERT INTO entries (key, input, sha256, load, kernel, db, state, created, accessed) "
                "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET accessed=excluded.accessed, "
                "input=excluded.input",
                (key, str(input_path), sha256, json.dumps(load, sort_keys=True), kernel_version(), str(db),
                 None, now, now),
            )
    except sqlite3.Error:
        pass


def set_state(key: str, state: str) -> None:
    try:
        with connect() as conn:
            conn.execute("UPDATE entries SET state=? WHERE key=?", (state, key))
    except sqlite3.Error:
        pass


def entries() -> list[dict]:
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM entries ORDER BY accessed DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        db = Path(d["db"])
        d["load"] = json.loads(d["load"] or "{}")
        d["size"] = db_size(db)
        d["exists"] = db.exists() or db.with_suffix(".id0").exists()
        out.append(d)
    return out


def db_size(db: Path) -> int:
    total = 0
    for suffix in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        p = db.with_suffix(suffix)
        if p.exists():
            total += p.stat().st_size
    return total


def remove_db_files(db: Path) -> int:
    n = 0
    for suffix in (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til", ".i64.lock"):
        p = db.with_suffix(suffix) if not suffix.endswith(".lock") else Path(str(db) + ".lock")
        if p.exists():
            p.unlink()
            n += 1
    try:
        db.parent.rmdir()
    except OSError:
        pass
    return n


def forget(key: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM entries WHERE key=?", (key,))


# -- handles (@name) ------------------------------------------------------------------


def set_handle(name: str, target: str) -> None:
    with connect() as conn:
        conn.execute("INSERT OR REPLACE INTO handles VALUES (?,?,?)", (name, target, time.time()))


def get_handle(name: str) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT target FROM handles WHERE name=?", (name,)).fetchone()
    return row[0] if row else None


def last_target_file() -> Path:
    return cache_dir() / "last-target"


def remember_last(target: str) -> None:
    try:
        cache_dir().mkdir(parents=True, exist_ok=True)
        last_target_file().write_text(target)
    except OSError:
        pass


def last_target() -> str | None:
    v = os.environ.get("ICLI_LAST") or os.environ.get("IDX_LAST")
    if v:
        return v
    try:
        return last_target_file().read_text().strip() or None
    except OSError:
        return None
