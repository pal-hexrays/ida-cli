"""icli configuration files (CONFIGURATION in idx(1)).

Precedence, highest first: command line, ICLI_*/IDX_* environment,
``.icli.toml`` (or ``.idx.toml``) in the current directory or nearest parent
(stopping at a ``.git`` directory), ``$IDAUSR/icli.toml``,
``$IDADIR/cfg/icli.toml``, built-in defaults.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from ..errors import usage

PROJECT_NAMES = (".icli.toml", ".idx.toml")


class _Config(dict):
    """Merged configuration, loaded on first access."""

    _loaded = False

    def _load(self) -> None:
        if not self._loaded:
            self._loaded = True
            for path in reversed(layer_paths()):
                if path is not None and path.is_file():
                    _merge(self, read(path))

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        self._load()
        return super().get(key, default)

    def __getitem__(self, key: str) -> Any:
        self._load()
        return super().__getitem__(key)

    def reload(self) -> None:
        self.clear()
        self._loaded = False


CONFIG = _Config()


def _merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = v


def read(path: Path) -> dict:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as error:
        raise usage(f"{path}: invalid TOML: {error}")
    except OSError:
        return {}


def project_path(start: Path | None = None, *, create: bool = False) -> Path | None:
    d = (start or Path.cwd()).resolve()
    for p in [d, *d.parents]:
        for name in PROJECT_NAMES:
            if (p / name).is_file():
                return p / name
        if (p / ".git").exists():
            break
    return (start or Path.cwd()) / PROJECT_NAMES[0] if create else None


def global_path() -> Path:
    from .env import icli_home

    return icli_home() / "icli.toml"


def system_path() -> Path | None:
    from .env import idadir

    d = idadir()
    return d / "cfg" / "icli.toml" if d else None


def layer_paths() -> list[Path | None]:
    """Highest precedence first."""
    return [project_path(), global_path(), system_path()]


def default(section: str, key: str, fallback: Any = None) -> Any:
    sec = CONFIG.get(section) or {}
    return sec.get(key, sec.get(key.replace("_", "-"), fallback))


# -- writing ---------------------------------------------------------------------------


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(str(v))


def dump(data: dict) -> str:
    lines: list[str] = []
    for k, v in data.items():
        if not isinstance(v, dict):
            lines.append(f"{k} = {_toml_value(v)}")
    for k, v in data.items():
        if isinstance(v, dict):
            if lines:
                lines.append("")
            lines.append(f"[{k}]")
            for kk, vv in v.items():
                key = kk if kk.replace("_", "").replace("-", "").isalnum() else json.dumps(kk)
                lines.append(f"{key} = {_toml_value(vv)}")
    return "\n".join(lines) + "\n"


def split_key(key: str) -> tuple[str, str]:
    section, dot, name = key.partition(".")
    if not dot or not section or not name:
        raise usage(f"configuration keys are section.name (e.g. defaults.format), not {key!r}")
    return section, name


def parse_value(text: str) -> Any:
    try:
        return tomllib.loads(f"v = {text}")["v"]
    except tomllib.TOMLDecodeError:
        return text
