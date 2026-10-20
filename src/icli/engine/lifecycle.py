"""Analysis lifecycle: loaded -> analyzing -> analyzed -> enriched."""

from __future__ import annotations

import ida_auto

from .store import Doc

STATES = ["loaded", "analyzing", "analyzed", "enriched"]
_DOC = Doc("$icli.state")


def _doc() -> dict:
    return _DOC.load({}) or {}


def state() -> str:
    d = _doc()
    if ida_auto.auto_is_ok():
        if d.get("enriched"):
            return "enriched"
        if d.get("started") or d.get("analyzed") or not d:
            # databases created outside icli have been analysed by IDA
            return "analyzed"
        return "loaded"
    return "analyzing" if d.get("started") or d.get("analyzed") else "loaded"


def mark(**fields: object) -> dict:
    d = _doc()
    for k, v in fields.items():
        if v is None:
            d.pop(k, None)
        elif k == "enriched" and isinstance(v, list):
            d["enriched"] = sorted(set(d.get("enriched", [])) | set(v))
        else:
            d[k] = v
    _DOC.save(d)
    return d


def info() -> dict:
    d = _doc()
    return {"state": state(), "passes": d.get("enriched", []), "started": bool(d.get("started"))}


QUEUES = [
    ("unknown", "AU_UNK"), ("code", "AU_CODE"), ("weak_code", "AU_WEAK"), ("proc", "AU_PROC"),
    ("tail", "AU_TAIL"), ("fchunk", "AU_FCHUNK"), ("used", "AU_USED"), ("used_type", "AU_USD2"),
    ("type", "AU_TYPE"), ("libfunc", "AU_LIBF"), ("lbf2", "AU_LBF2"), ("lbf3", "AU_LBF3"),
    ("chlb", "AU_CHLB"), ("final", "AU_FINAL"),
]


def pending() -> dict[str, int]:
    """Items pending per analysis queue (0 when the queue is empty)."""
    import ida_ida
    import ida_idaapi

    out: dict[str, int] = {}
    lo = ida_ida.inf_get_min_ea()
    for name, const in QUEUES:
        q = getattr(ida_auto, const, None)
        if q is None:
            continue
        ea = ida_auto.peek_auto_queue(lo, q)
        out[name] = 0 if ea == ida_idaapi.BADADDR else 1
    return out
