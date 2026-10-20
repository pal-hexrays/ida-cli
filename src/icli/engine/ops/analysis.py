"""Load-time setup, analysis preparation and optional analysis passes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_segment

from ...errors import Exit, IdaxError
from .. import decomp
from ..context import A, Ctx
from ..rpc import op

BADADDR = ida_idaapi.BADADDR


@op("settings.hexrays")
def settings_hexrays(ctx: Ctx, directives: list[str]) -> list:
    if not decomp.available():
        return []
    import ida_hexrays

    for d in directives:
        if not ida_hexrays.change_hexrays_config(d):
            raise IdaxError(Exit.USAGE, f"--set hexrays: rejected {d!r}", "USAGE")
    return []


# -- post-load (LOAD OPTIONS that need the loaded database) ---------------------------------------


def create_segment(name: str, start: int, end: int, cls: str | None = None, perm: str | None = None,
                   file: str | None = None, offset: int = 0, bitness: int | None = None) -> None:
    seg = ida_segment.segment_t()
    seg.start_ea, seg.end_ea = start, end
    seg.bitness = {16: 0, 32: 1, 64: 2}.get(bitness or (64 if ida_ida.inf_is_64bit() else 32), 1)
    if perm:
        p = 0
        p |= ida_segment.SEGPERM_READ if "r" in perm else 0
        p |= ida_segment.SEGPERM_WRITE if "w" in perm else 0
        p |= ida_segment.SEGPERM_EXEC if "x" in perm else 0
        seg.perm = p
    if not ida_segment.add_segm_ex(seg, name, cls or "DATA", ida_segment.ADDSEG_NOSREG):
        raise IdaxError(Exit.LOAD, f"cannot create segment {name} {start:#x}-{end:#x}", "LOAD")
    if file:
        data = Path(file).read_bytes()[offset: offset + (end - start)]
        ida_bytes.put_bytes(start, data)


def load_svd(path: str) -> int:
    """Create peripheral segments and register names from a CMSIS-SVD file."""
    import xml.etree.ElementTree as ET

    def num(text: str | None, default: int = 0) -> int:
        if not text:
            return default
        t = text.strip().lower()
        return int(t, 16) if t.startswith("0x") else int(t, 0)

    root = ET.parse(path).getroot()
    count = 0
    peripherals = root.find("peripherals")
    if peripherals is None:
        raise IdaxError(Exit.LOAD, f"{path}: no <peripherals>", "LOAD")
    by_name = {p.findtext("name"): p for p in peripherals.findall("peripheral")}
    for p in peripherals.findall("peripheral"):
        name = p.findtext("name") or "PERIPH"
        base = num(p.findtext("baseAddress"))
        regs_src = p
        derived = p.get("derivedFrom")
        if derived and p.find("registers") is None and derived in by_name:
            regs_src = by_name[derived]
        size = 0
        for blk in regs_src.findall("addressBlock"):
            size = max(size, num(blk.findtext("offset")) + num(blk.findtext("size")))
        size = size or 0x400
        if ida_segment.getseg(base) is None:
            create_segment(name, base, base + size, "IO", "rw")
        regs = regs_src.find("registers")
        for r in (regs.findall("register") if regs is not None else []):
            rname = r.findtext("name") or "REG"
            off = num(r.findtext("addressOffset"))
            rsize = num(r.findtext("size"), 32) // 8
            ea = base + off
            {1: ida_bytes.create_byte, 2: ida_bytes.create_word, 4: ida_bytes.create_dword,
             8: ida_bytes.create_qword}.get(rsize, ida_bytes.create_dword)(ea, rsize, True)
            ida_name.set_name(ea, f"{name}_{rname}", ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            desc = r.findtext("description")
            if desc:
                ida_bytes.set_cmt(ea, " ".join(desc.split()), False)
            count += 1
    return count


@op("load.post")
def load_post(ctx: Ctx, **post: Any) -> list[dict]:
    out = []
    if post.get("bitness"):
        b = int(post["bitness"])
        if b == 64:
            ida_ida.inf_set_64bit(True)
        elif b == 32:
            ida_ida.inf_set_64bit(False)
            ida_ida.inf_set_32bit(True)
        else:
            ida_ida.inf_set_64bit(False)
            ida_ida.inf_set_32bit(False)
        code = {16: 0, 32: 1, 64: 2}[b]
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            ida_segment.set_segm_addressing(s, code)
        out.append({"_t": "load", "option": "bitness", "value": b})
    if post.get("endian"):
        ida_ida.inf_set_be(post["endian"] == "big")
        out.append({"_t": "load", "option": "endian", "value": post["endian"]})
    for seg in post.get("segments") or []:
        create_segment(seg["name"], seg["start"], seg["end"], seg.get("class"), seg.get("perm"), seg.get("file"),
                       seg.get("offset", 0))
        ida_auto.plan_range(seg["start"], seg["end"])
        out.append({"_t": "load", "option": "segment", "name": seg["name"], "ea": A(seg["start"]),
                    "end": A(seg["end"])})
    if post.get("svd"):
        n = load_svd(post["svd"])
        out.append({"_t": "load", "option": "svd", "registers": n})
    if post.get("encoding"):
        import ida_nalt

        idx = ida_nalt.add_encoding(post["encoding"])
        if idx <= 0:
            raise IdaxError(Exit.USAGE, f"--encoding {post['encoding']}: unknown encoding", "USAGE")
        ida_nalt.set_default_encoding_idx(ida_nalt.BPU_1B, idx)
        out.append({"_t": "load", "option": "encoding", "value": post["encoding"]})
    for src in post.get("symbols") or []:
        if src == "none":
            continue
        from .knowledge import load_debug_info

        out.append(load_debug_info(src))
    if post.get("load_opts", {}).get("elf.debug_dir"):
        out.append({"_t": "load", "option": "elf.debug_dir", "value": post["load_opts"]["elf.debug_dir"]})
    ida_auto.enable_auto(True)
    return out


# -- analysis -----------------------------------------------------------------------


@op("analyze.prepare")
def analyze_prepare(ctx: Ctx, sigs: list[str] | None = None, tils: list[str] | None = None,
                    without: list[str] | None = None, reanalyze: bool = False,
                    selectors: list[dict] | None = None) -> list[dict]:
    out = []
    if "flirt" in (without or []):
        ida_ida.inf_set_af(ida_ida.inf_get_af() & ~ida_ida.AF_FLIRT)
    if "final" in (without or []) and hasattr(ida_ida, "AF_FINAL"):
        ida_ida.inf_set_af(ida_ida.inf_get_af() & ~ida_ida.AF_FINAL)
    for s in sigs or []:
        from .knowledge import apply_signature

        out.append(apply_signature(s, plan_only=True))
    for t in tils or []:
        import ida_typeinf

        if ida_typeinf.add_til(t, ida_typeinf.ADDTIL_DEFAULT) == ida_typeinf.ADDTIL_FAILED:
            raise IdaxError(Exit.NOT_FOUND, f"--til {t}: type library not found", "NOTFOUND")
        out.append({"_t": "til", "name": t, "status": "added"})
    if reanalyze:
        from .. import lifecycle

        lifecycle.mark(analyzed=None, enriched=None)
        ida_auto.plan_range(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
        lifecycle.mark(started=True)
    if selectors:
        from .. import select
        from .common import spans

        for s, e in spans(select.evaluate(ctx, selectors)):
            ida_auto.plan_range(s, e)
    ida_auto.enable_auto(True)
    return out


def _run_plugin(name: str, arg: int = 0) -> bool:
    return bool(ida_loader.load_and_run_plugin(name, arg))


def find_main() -> int | None:
    """Locate the program's real main and name it."""
    for n in ("main", "_main", "WinMain", "wWinMain", "_WinMain@16", "DllMain"):
        ea = ida_name.get_name_ea(BADADDR, n)
        if ea != BADADDR:
            return ea
    # ELF: the first argument of __libc_start_main is main; look at the
    # instructions preparing the call for a reference to a function start.
    import ida_ua
    import ida_xref

    for n in ("__libc_start_main", ".__libc_start_main", "__libc_start_main@@GLIBC_2.34",
              "__libc_start_main@@GLIBC_2.2.5"):
        target = ida_name.get_name_ea(BADADDR, n)
        if target == BADADDR:
            continue
        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(target, ida_xref.XREF_ALL)
        while ok:
            ea = xb.frm
            for _ in range(8):
                ea = ida_bytes.prev_head(ea, 0)
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    continue
                for opnd in insn.ops:
                    cand = opnd.addr or opnd.value
                    if opnd.type in (ida_ua.o_mem, ida_ua.o_imm, ida_ua.o_near):
                        f = ida_funcs.get_func(cand)
                        if f is not None and f.start_ea == cand:
                            return cand
            ok = xb.next_to()
    return None


PASS_PLUGINS = {"pdb": "pdb", "dwarf": "dwarf", "rtti": "rtti", "eh": "eh_parse", "golang": "golang",
                "rust": "rust", "swift": "swift", "objc": "objc"}


@op("analyze.pass")
def analyze_pass(ctx: Ctx, name: str) -> dict:
    if name in PASS_PLUGINS:
        ok = _run_plugin(PASS_PLUGINS[name])
        ida_auto.auto_wait()
        return {"_t": "pass", "name": name, "status": "ok" if ok else "unavailable"}
    if name == "findmain":
        ea = find_main()
        if ea is not None and ida_name.get_name(ea) not in ("main", "_main", "WinMain", "wWinMain"):
            ida_name.set_name(ea, "main", ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        return {"_t": "pass", "name": name, "status": "ok" if ea is not None else "notfound", "ea": A(ea)}
    if name == "decompile":
        decomp.require()
        done = failed = 0
        for i in range(ida_funcs.get_func_qty()):
            f = ida_funcs.getn_func(i)
            if f.flags & ida_funcs.FUNC_LIB:
                continue
            r = decomp.decompile(f.start_ea)
            done += 1
            failed += 0 if r.ok else 1
        return {"_t": "pass", "name": name, "status": "ok", "decompiled": done, "failed": failed}
    if name == "lumina":
        from .knowledge import lumina_pull

        recs = lumina_pull(ctx, None, apply=True)
        return {"_t": "pass", "name": name, "status": "ok", "applied": len(recs)}
    raise IdaxError(Exit.USAGE, f"unknown pass {name}", "USAGE")
