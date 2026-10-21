"""Engine entry point, executed inside IDA through ida-nexus.

The client sends ``call(db, request_json)`` as the trailing expression of an
``execute_python`` snippet; the return value is a JSON-compatible dict:

    {"records": [...], "warnings": [...], "status": int, "raw": [...], "meta": {...}}
    {"error": {"status", "message", "code"}, "warnings": [...]}
"""

from __future__ import annotations

import json
import traceback
from typing import Any, Callable

from ..errors import Exit, IcliError
from .context import Addr, Ctx, Options

DIGEST: str | None = None

OpFn = Callable[..., Any]
OPS: dict[str, OpFn] = {}


def op(name: str) -> Callable[[OpFn], OpFn]:
    """Register an engine operation callable as ``fn(ctx, **params)``.

    The function may return an iterable of records (dicts), a single dict, or
    ``None`` (records already emitted through the context)."""

    def deco(fn: OpFn) -> OpFn:
        if name in OPS:
            raise RuntimeError(f"duplicate engine op {name}")
        OPS[name] = fn
        return fn

    return deco


def _load_ops() -> None:
    if not OPS:
        from . import ops  # noqa: F401  (registers every op)


def call(db: Any, request: str) -> dict:
    req = json.loads(request)
    ctx = Ctx(db=db, opts=Options.from_dict(req.get("ctx", {})), prev=req.get("prev") or [])
    try:
        _load_ops()
        fn = OPS.get(req["op"])
        if fn is None:
            raise IcliError(Exit.USAGE, f"unknown engine operation {req['op']!r}", "USAGE")
        result = fn(ctx, **req.get("params", {}))
        records = _collect(result)
        render = _renderer(ctx)
        return {
            "records": [render(r) for r in records],
            "warnings": ctx.warnings,
            "status": ctx.status,
            "raw": ctx.raw,
            "extra": render(ctx.extra),
        }
    except IcliError as error:
        return {"error": error.to_dict(), "warnings": ctx.warnings}
    except KeyboardInterrupt:
        raise
    except BaseException as error:  # noqa: BLE001 - reported as INTERR
        return {
            "error": {
                "status": int(Exit.INTERNAL),
                "message": f"internal error: {type(error).__name__}: {error}\n{traceback.format_exc()}",
                "code": "INTERR",
            },
            "warnings": ctx.warnings,
        }


def _collect(result: Any) -> list[dict]:
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    return list(result)


def _renderer(ctx: Ctx) -> Callable[[Any], Any]:
    from .addresses import format_address

    style = ctx.opts.addr

    def render(value: Any) -> Any:
        if isinstance(value, Addr):
            return format_address(int(value), style)
        if isinstance(value, dict):
            return {k: render(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [render(v) for v in value]
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, float) and value != value:  # NaN is not JSON
            return None
        return value

    return render
