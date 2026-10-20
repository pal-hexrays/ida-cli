"""Hex-Rays access with per-call caching and error reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import ida_funcs
import ida_idaapi
import ida_lines

from ..errors import Exit, IdaxError

_available: bool | None = None


def available() -> bool:
    global _available
    if _available is None:
        try:
            import ida_hexrays

            _available = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            _available = False
    return _available


def require() -> None:
    if not available():
        import ida_ida

        raise IdaxError(
            Exit.LICENSE,
            f"no decompiler available for processor {ida_ida.inf_get_procname()}",
            "LICENSE",
        )


@dataclass
class Result:
    ea: int
    cfunc: Any = None
    err: int = 0
    message: str = ""
    err_ea: int | None = None

    @property
    def ok(self) -> bool:
        return self.cfunc is not None

    @property
    def text(self) -> str:
        if self.cfunc is None:
            return ""
        return "\n".join(ida_lines.tag_remove(line.line) for line in self.cfunc.get_pseudocode())


_cache: dict[tuple[int, bool], Result] = {}


def reset() -> None:
    _cache.clear()


def decompile(ea: int, fresh: bool = False) -> Result:
    """Decompile the function containing ``ea``; never raises for decompiler
    failures (they are reported in the result)."""
    require()
    import ida_hexrays

    f = ida_funcs.get_func(ea)
    if f is None:
        return Result(ea, err=-1, message=f"no function at {ea:#x}", err_ea=ea)
    key = (f.start_ea, fresh)
    hit = _cache.get((f.start_ea, False)) if not fresh else None
    if hit is not None:
        return hit
    hf = ida_hexrays.hexrays_failure_t()
    flags = ida_hexrays.DECOMP_NO_WAIT
    if fresh:
        flags |= ida_hexrays.DECOMP_NO_CACHE
        ida_hexrays.mark_cfunc_dirty(f.start_ea)
    try:
        cf = ida_hexrays.decompile_func(f, hf, flags)
    except Exception as error:  # DecompilationFailure on some versions
        cf = None
        if not hf.code:
            hf.code = -1
            hf.desc_ = str(error)  # type: ignore[attr-defined]
    if cf is None:
        try:
            desc = hf.desc()
        except Exception:
            desc = getattr(hf, "str", "") or "decompilation failed"
        errea = int(hf.errea)
        res = Result(f.start_ea, None, int(hf.code) or -1, desc,
                     None if errea == ida_idaapi.BADADDR else errea)
    else:
        res = Result(f.start_ea, cf)
    _cache[key] = res
    return res


def has_cached(ea: int) -> bool:
    try:
        import ida_hexrays

        return bool(ida_hexrays.has_cached_cfunc(ea))
    except Exception:
        return False


MATURITIES = {
    "generated": "MMAT_GENERATED",
    "preoptimized": "MMAT_PREOPTIMIZED",
    "locopt": "MMAT_LOCOPT",
    "calls": "MMAT_CALLS",
    "glbopt1": "MMAT_GLBOPT1",
    "glbopt2": "MMAT_GLBOPT2",
    "glbopt3": "MMAT_GLBOPT3",
    "lvars": "MMAT_LVARS",
}


def microcode(ea: int, maturity: str = "lvars") -> str:
    """Text of the microcode of the function containing ``ea``."""
    require()
    import ida_hexrays

    if maturity not in MATURITIES:
        raise IdaxError(Exit.USAGE, f"unknown maturity {maturity!r}; one of {', '.join(MATURITIES)}", "USAGE")
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdaxError(Exit.EMPTY_SELECTION, f"no function at {ea:#x}", "NOMATCH")
    mbr = ida_hexrays.mba_ranges_t(f)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS,
                                    getattr(ida_hexrays, MATURITIES[maturity]))
    if mba is None:
        raise IdaxError(Exit.DECOMPILE, f"{ea:#x}: microcode generation failed: {hf.desc()}", "HEXRAYS")

    class _Printer(ida_hexrays.vd_printer_t):
        def __init__(self) -> None:
            super().__init__()
            self.lines: list[str] = []

        def _print(self, indent: int, line: str) -> int:  # noqa: N802 (SDK name)
            self.lines.append(ida_lines.tag_remove(line))
            return 1

    p = _Printer()
    mba._print(p)
    return "\n".join(p.lines)
