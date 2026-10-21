"""``vault://site/path[@rev]`` targets (IDA Teams, through hv)."""

from __future__ import annotations

import re
from pathlib import Path

from ..errors import Exit, IcliError, usage

_SPEC = re.compile(r"^vault://(?P<site>[^/]+)/(?P<path>[^@]+?)(?:@(?P<rev>\d+))?$")


def parse_spec(spec: str) -> dict:
    m = _SPEC.match(spec)
    if not m:
        raise usage(f"bad vault target {spec!r}: expected vault://site/path[@rev]")
    return {"site": m.group("site"), "path": m.group("path"), "rev": m.group("rev")}


def site_root(site: str) -> Path | None:
    """The local directory a site maps vault paths to (``hv sites SITE``)."""
    from .commands.storage import run_hv

    res = run_hv(["sites", site])
    for line in res.stdout.splitlines():
        m = re.search(r"(?:root|directory|path)\s*[:=]\s*(\S.*)$", line, re.I)
        if m:
            return Path(m.group(1).strip())
    return None


def local_path(spec: dict) -> Path | None:
    if not spec.get("site"):
        return Path(spec["path"]).resolve()
    root = site_root(spec["site"])
    return (root / spec["path"].lstrip("/")) if root else None


def checkout(spec: str) -> Path:
    """Sync and check out a vault database; returns its local path."""
    from .commands.storage import run_hv

    s = parse_spec(spec)
    target = f"{s['path']}#{s['rev']}" if s["rev"] else s["path"]
    run_hv(["sync", "-s", target], site=s["site"])
    if not s["rev"]:
        run_hv(["edit", "-s", s["path"]], site=s["site"])
    p = local_path(s)
    if p is None or not p.exists():
        raise IcliError(Exit.NETWORK, f"{spec}: checked out, but its local path is unknown", "VAULT")
    return p
