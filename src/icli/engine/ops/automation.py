"""exec and assert."""

from __future__ import annotations

import re
from typing import Any

from ...errors import Exit, IdaxError
from .. import execution, select
from ..context import Ctx
from ..rpc import op


@op("exec")
def exec_(ctx: Ctx, code: str, filename: str = "<icli>", args: list[str] | None = None,
          each: list[dict] | None = None, session: str | None = None, lang: str = "py", no_save: bool = False,
          record_code: bool = True) -> list[dict]:
    records, out, err, status = execution.run(ctx, code, filename=filename, args=args, each=each, session=session,
                                               lang=lang, no_save=no_save, record_code=record_code)
    ctx.set_status(status)
    # the code's own stdout/stderr travel apart from the records
    ctx.extra.update({"stdout": out, "stderr": err})
    return records


_COND = re.compile(r"^\s*(==|!=|<=|>=|<|>)\s*(\d+)\s*$")


@op("assert")
def assert_(ctx: Ctx, selectors: list[dict], cond: str, limit: int = 50) -> list[dict]:
    m = _COND.match(cond)
    if not m:
        raise IdaxError(Exit.USAGE, f"bad condition {cond!r}: expected (==|!=|<|<=|>|>=) N", "USAGE")
    opname, n = m.group(1), int(m.group(2))
    sel = select.evaluate(ctx, selectors)
    count = len(sel)
    ok = {"==": count == n, "!=": count != n, "<": count < n, "<=": count <= n, ">": count > n,
          ">=": count >= n}[opname]
    if ok:
        return []
    ctx.set_status(Exit.NEGATIVE)
    out: list[dict[str, Any]] = [{"_t": "assert", "count": count, "cond": cond.strip(), "ok": False}]
    for i, it in enumerate(sel):
        if i >= limit:
            break
        out.append(it.kind.to_record(it, ctx, None))
    return out
