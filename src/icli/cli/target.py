"""Targets (CONCEPTS / Targets in icli(1)): databases, input files, container
members, vault:// databases and @handles."""

from __future__ import annotations

import os
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import Exit, IcliError, usage
from . import cache
from .env import cache_dir, env

DB_SUFFIXES = (".i64", ".idb")


@dataclass
class Target:
    spec: str
    input: Path | None = None      # the analysed input file (None for a bare database)
    db: Path | None = None         # the database path
    key: str | None = None         # cache key, when the database lives in the cache
    load: dict[str, Any] = field(default_factory=dict)
    temporary: bool = False        # --no-cache
    vault: str | None = None

    @property
    def is_database(self) -> bool:
        return self.input is None

    def describe(self) -> dict:
        return {"spec": self.spec, "input": str(self.input) if self.input else None,
                "db": str(self.db) if self.db else None, "key": self.key}


def looks_like_target(text: str) -> bool:
    """Whether a positional argument denotes a target rather than a selector."""
    if text.startswith("vault://") or text == "@":
        return True
    if text.startswith("@"):
        # @name is a handle when registered; otherwise it is an @file selector
        return cache.get_handle(text[1:]) is not None
    if text.endswith(DB_SUFFIXES):
        return True
    path, sep, _ = text.partition("::")
    if sep:
        return Path(path).exists()
    return Path(text).is_file()


def default_target() -> str | None:
    v = env("DB")
    if v:
        return v
    dbs = sorted(p for p in Path.cwd().iterdir() if p.suffix == ".i64" and p.is_file())
    if len(dbs) == 1:
        return str(dbs[0])
    return None


def split_target(items: list[str], *, minimum_rest: int = 0) -> tuple[str | None, list[str]]:
    """Split positionals into (target, rest).

    The first positional is the target when it looks like one, or when no
    default target exists.  ``minimum_rest`` positionals must remain (e.g.
    ``rename sel name``)."""
    if items and looks_like_target(items[0]):
        return items[0], items[1:]
    default = default_target()
    if default is not None and len(items) >= minimum_rest:
        return default, items
    if not items:
        raise IcliError(Exit.USAGE, "no target: give a database or input file (or set ICLI_DB)", "USAGE")
    return items[0], items[1:]


def resolve(spec: str, load: dict[str, Any], *, db: str | None = None, no_cache: bool = False,
            create: bool = True) -> Target:
    """Resolve a target specification to input and database paths.

    ``create=False`` computes the cache path without creating directories
    or index entries (``db path``, ``cache key``)."""
    original = spec
    if spec == "@":
        last = cache.last_target()
        if not last:
            raise usage("'@' (previous target) is not set in this shell")
        spec = last
    elif spec.startswith("@"):
        handle = cache.get_handle(spec[1:])
        if handle is None:
            raise usage(f"unknown handle {spec!r} (register one with: icli db tag NAME TARGET)")
        spec = handle
    if spec.startswith("vault://"):
        from .vault import checkout

        local = checkout(spec)
        t = resolve(str(local), load, db=db, no_cache=no_cache, create=create)
        t.vault = spec
        t.spec = original
        return t

    if spec.endswith(DB_SUFFIXES):
        p = Path(spec).expanduser().resolve()
        if not p.exists() and not p.with_suffix(".id0").exists():
            raise IcliError(Exit.NOT_FOUND, f"{spec}: database not found", "NOTFOUND")
        if load:
            raise usage("load options apply to input files, not to an existing database "
                        f"({', '.join(sorted(load))})")
        if p.suffix == ".idb" and create:
            from .local import upgrade_idb

            p = upgrade_idb(p)  # a legacy .idb is upgraded to .i64 on first use
        return Target(original, None, p)

    member = None
    container, sep, rest = spec.partition("::")
    if sep:
        spec, member = container, rest
    p = Path(spec).expanduser()
    if not p.exists():
        raise IcliError(Exit.NOT_FOUND, f"{spec}: no such file", "NOTFOUND")
    if not p.is_file() and not (p.is_dir() and member):
        raise IcliError(Exit.NOT_FOUND, f"{spec}: not a regular file", "NOTFOUND")
    p = p.resolve()
    if member:
        p = extract_member(p, member)
    try:
        sha = cache.file_sha256(p)
    except OSError as error:
        raise IcliError(Exit.NOT_FOUND, f"{spec}: {error.strerror}", "NOTFOUND")
    if db:
        dbp = Path(db).expanduser().resolve()
        return Target(original, p, dbp, None, load)
    if no_cache:
        import tempfile

        tmp = Path(tempfile.mkdtemp(prefix="icli-", dir=os.environ.get("TMPDIR")))
        return Target(original, p, tmp / (p.name + ".i64"), None, load, temporary=True)
    key = cache.cache_key(sha, load)
    dbp = cache.db_path_for(key)
    if create:
        cache.ensure_dir(dbp.parent)
        cache.record(key, p, sha, load, dbp)
    return Target(original, p, dbp, key, load)


# -- container members --------------------------------------------------------------

_FAT_MAGICS = {0xCAFEBABE: (">", False), 0xCAFEBABF: (">", True)}
_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64",
        0x0200000C: "arm64_32"}


def fat_slices(path: Path) -> list[dict]:
    with path.open("rb") as fh:
        head = fh.read(8)
        if len(head) < 8:
            return []
        magic = struct.unpack(">I", head[:4])[0]
        if magic not in _FAT_MAGICS:
            return []
        _, wide = _FAT_MAGICS[magic]
        n = struct.unpack(">I", head[4:8])[0]
        if n > 64:  # Java class files share the 0xCAFEBABE magic
            return []
        out = []
        for i in range(n):
            if wide:
                cpu, sub, off, size, align, _ = struct.unpack(">iiQQII", fh.read(32))
            else:
                cpu, sub, off, size, align = struct.unpack(">iiIII", fh.read(20))
            name = _CPU.get(cpu & 0xFFFFFFFF, f"cpu{cpu}")
            if name == "arm64" and (sub & 0xFF) == 2:
                name = "arm64e"
            out.append({"index": i, "arch": name, "offset": off, "size": size})
        return out


def extract_member(container: Path, member: str) -> Path:
    """Materialise ``container::member`` in the cache (content-addressed)."""
    sha = cache.file_sha256(container)
    dest_dir = cache_dir() / "members" / sha[:16]
    safe = member.replace("/", "_").replace("\\", "_").replace("..", "_")
    dest = dest_dir / f"{container.name}__{safe}"
    if dest.exists():
        return dest
    data: bytes | None = None
    if container.is_dir():
        # Foo.app/Contents/MacOS/Foo::arm64 style where the left side is a bundle dir
        raise IcliError(Exit.NOT_FOUND, f"{container}: is a directory", "NOTFOUND")
    slices = fat_slices(container)
    if slices:
        match = [s for s in slices if s["arch"] == member or str(s["index"]) == member]
        if not match:
            archs = ", ".join(s["arch"] for s in slices)
            raise IcliError(Exit.EMPTY_SELECTION, f"{container.name}: no slice {member!r} (has {archs})",
                            "NOMATCH")
        s = match[0]
        with container.open("rb") as fh:
            fh.seek(s["offset"])
            data = fh.read(s["size"])
    elif zipfile.is_zipfile(container):
        with zipfile.ZipFile(container) as z:
            try:
                data = z.read(member)
            except KeyError:
                raise IcliError(Exit.EMPTY_SELECTION, f"{container.name}: no member {member!r}", "NOMATCH")
    elif container.name.startswith("dyld_shared_cache"):
        raise IcliError(Exit.LOAD, f"{container.name}: select dyld cache modules with "
                        f"--load-opt dsc.modules={member}", "LOAD")
    else:
        raise IcliError(Exit.LOAD, f"{container.name}: not a container (fat Mach-O, zip, apk)", "LOAD")
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)
    return dest
