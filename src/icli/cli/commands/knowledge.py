"""Knowledge: sig, til, lumina, load."""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ...errors import Exit, IdaxError, usage
from ...lang.values import parse_address_number, parse_int
from ..env import idadir, idausr
from ..registry import Command, Invocation, register
from .edit import Edit


def _need_file(p: str) -> Path:
    path = Path(p).expanduser()
    if not path.exists():
        raise IdaxError(Exit.NOT_FOUND, f"{p}: no such file", "NOTFOUND")
    return path.resolve()


# -- FLIRT -------------------------------------------------------------------------------------


def sig_header(path: Path) -> dict:
    """Header of a FLIRT .sig file (library name, counts)."""
    data = path.read_bytes()[:256]
    if not data.startswith(b"IDASGN"):
        return {"name": path.stem, "title": None, "valid": False}
    version = data[6]
    off = 7
    arch = data[off]
    off += 1
    file_types, os_types, app_types, features, old_n, crc16 = struct.unpack_from("<IHHHHH", data, off)
    off += 14
    off += 12  # ctype
    name_len = data[off]
    off += 1
    off += 2  # ctypes crc
    n_functions = old_n
    if version >= 6:
        n_functions = struct.unpack_from("<I", data, off)[0]
        off += 4
    if version >= 8:
        off += 2
    if version >= 10:
        off += 2
    if version >= 11:
        off += 1
    title = data[off:off + name_len].decode("latin-1", "replace")
    return {"name": path.stem, "title": title, "version": version, "arch": arch, "functions": n_functions,
            "valid": True, "features": features, "file_types": file_types, "os_types": os_types,
            "app_types": app_types, "crc16": crc16}


PROC_DIRS = {"metapc": "pc", "pc": "pc"}


def sig_files(processor: str | None) -> list[Path]:
    out: list[Path] = []
    for base in (idausr() / "sig", (idadir() or Path("/nonexistent")) / "sig"):
        if not base.is_dir():
            continue
        dirs = [base / PROC_DIRS.get(processor, processor)] if processor else [d for d in base.iterdir()
                                                                                 if d.is_dir()]
        for d in dirs:
            if d.is_dir():
                out.extend(sorted(d.glob("*.sig")))
    return out


def _flair(tool: str) -> Path:
    d = idadir()
    p = d / "tools" / "flair" / tool if d else None
    if p is None or not p.exists():
        raise IdaxError(Exit.LICENSE, f"FLAIR tool {tool} not found in the IDA installation", "NOTOOL")
    return p


def _library_parser(lib: Path) -> str:
    data = lib.read_bytes()[:4096]
    if not data.startswith(b"!<arch>\n"):
        raise usage(f"{lib}: not a static library (ar archive)")
    if b"\x7fELF" in data:
        return "pelf"
    if b"\xcf\xfa\xed\xfe" in data or b"\xce\xfa\xed\xfe" in data:
        return "pmacho"
    return "pcf"


def _run(cmd: list[str], what: str) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise IdaxError(Exit.LOAD, f"{what} failed: {(res.stderr or res.stdout).strip()[-800:]}", "FLAIR")
    return res


def resolve_exc(exc: Path, policy: str) -> int:
    """Edit sigmake's collision file non-interactively.  Returns the number
    of collision groups.  skip: exclude every colliding function; first:
    keep the first member of each group."""
    lines = exc.read_text(errors="replace").splitlines()
    body = [ln for ln in lines if not ln.startswith(";")]
    groups = 0
    out: list[str] = []
    in_group = False
    for ln in body:
        if not ln.strip():
            in_group = False
            out.append(ln)
            continue
        if not in_group:
            groups += 1
            in_group = True
            out.append(("+" + ln) if policy == "first" and not ln.startswith(("+", "-")) else ln)
        else:
            out.append(ln)
    exc.write_text("\n".join(out) + "\n")
    return groups


@register
class Sig(Edit):
    name = "sig"
    group = "knowledge"
    summary = "FLIRT signatures: apply, match, make, list"
    subcommands = {"apply": "apply .sig files (or auto)", "match": "what a signature would rename",
                   "make": "build signatures from databases or static libraries", "list": "available .sig files"}
    target = "optional"
    overrides = frozenset({"--processor"})

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        if sub == "make":
            p.add_argument("-o", dest="output", required=True, metavar="OUT.sig")
            p.add_argument("--library-name", metavar="TEXT")
            p.add_argument("--select", metavar="SEL", help="which functions of database sources")
            p.add_argument("--pat-only", action="store_true")
            p.add_argument("--collisions", choices=("fail", "skip", "first"), default="fail")
        if sub == "list":
            p.add_argument("--processor", dest="sig_processor", metavar="P")
        if sub in ("apply", "match"):
            from .base import add_edit_options

            add_edit_options(p)

    def run(self, inv: Invocation) -> int:
        sub = inv.args.sub
        if sub == "list":
            out = []
            for f in sig_files(inv.args.sig_processor):
                h = sig_header(f)
                out.append({"_t": "sig", "name": f.stem, "title": h.get("title"), "functions": h.get("functions"),
                            "processor": f.parent.name, "path": str(f)})
            inv.emit(out)
            return 0 if out else Exit.NEGATIVE
        if sub == "apply":
            rest = inv.positionals(1)
            if not rest:
                raise usage("icli sig apply: expected signature name(s), a path, or auto")
            names = [str(_need_file(n)) if ("/" in n or n.endswith(".sig")) and n != "auto" and Path(n).exists()
                     else n for n in rest]
            return self.call(inv, "sig.apply", {"names": names})
        if sub == "match":
            return self._match(inv)
        if sub == "make":
            return self._make(inv)
        raise usage(f"icli sig: unknown subcommand {sub}")

    def _match(self, inv: Invocation) -> int:
        """Apply in a scratch copy of the database and report the library
        functions it produced; the real database is untouched."""
        from ..opening import open_session
        from ..options import GlobalOptions

        rest = inv.positionals(1)
        if not rest:
            raise usage("icli sig match: expected signature name(s)")
        session = inv.open()
        session.ensure("analyzed")
        session.save()
        before = {r["ea"] for r in session.call("sig.lib_functions", {})["records"]}
        tmp = Path(tempfile.mkdtemp(prefix="icli-sigmatch-"))
        try:
            src = session.target.db
            shutil.copy2(src, tmp / "scratch.i64")
            g = GlobalOptions()
            g.output.quiet = True
            scratch = open_session(str(tmp / "scratch.i64"), g, inv.emitter.diag)
            try:
                for name in rest:
                    nm = str(_need_file(name)) if Path(name).exists() else name
                    scratch.call("sig.apply", {"names": [nm]}, ctx={"addr": inv.g.addr})
                    after = scratch.call("sig.lib_functions", {}, ctx={"addr": inv.g.addr})["records"]
                    inv.emit([dict(r, sig=name) for r in after if r["ea"] not in before])
            finally:
                scratch.close(save=False)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return 0

    def _make(self, inv: Invocation) -> int:
        from ..opening import open_session

        a = inv.args
        sources = a.items
        if not sources:
            raise usage("icli sig make: expected source database(s) or static librar(y|ies)")
        out = Path(a.output).expanduser().resolve()
        work = Path(tempfile.mkdtemp(prefix="icli-sigmake-"))
        try:
            pats: list[Path] = []
            for i, src in enumerate(sources):
                path = _need_file(src)
                pat = work / f"src{i}.pat"
                if path.suffix in (".a", ".lib") or path.read_bytes()[:8] == b"!<arch>\n":
                    parser = _library_parser(path)
                    _run([str(_flair(parser)), str(path), str(pat)], parser)
                else:
                    s = open_session(str(path), inv.g, inv.emitter.diag)
                    try:
                        sels = inv.selectors([a.select]) if a.select else None
                        res = s.call("sig.patterns", {"selectors": sels})
                        for w in res.get("warnings", []):
                            inv.emitter.diag(w["level"], w["code"], w["msg"])
                        pat.write_text(res["records"][0]["text"])
                    finally:
                        s.close(save=False)
                pats.append(pat)
            if a.pat_only:
                text = "".join(p.read_text().replace("---\n", "") for p in pats) + "---\n"
                out.write_text(text)
                inv.emit([{"_t": "pat", "path": str(out), "patterns": text.count("\n") - 1}])
                return 0
            libname = a.library_name or out.stem
            cmd = [str(_flair("sigmake")), f"-n{libname}", *[str(p) for p in pats], str(out)]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=work)
            exc = out.with_suffix(".exc")
            collisions = 0
            if not out.exists() and exc.exists():
                if a.collisions == "fail":
                    groups = resolve_exc(exc, "fail")
                    exc.unlink()
                    raise IdaxError(Exit.CONFLICT, f"{groups} collision group(s) (use --collisions skip|first)",
                                    "CONFLICT")
                collisions = resolve_exc(exc, a.collisions)
                res = subprocess.run(cmd, capture_output=True, text=True, cwd=work)
                exc.unlink(missing_ok=True)
            if not out.exists():
                raise IdaxError(Exit.LOAD, f"sigmake failed: {(res.stderr or res.stdout).strip()[-800:]}", "FLAIR")
            h = sig_header(out)
            inv.emit([{"_t": "sig", "path": str(out), "title": h.get("title"), "functions": h.get("functions"),
                       "collisions": collisions, "policy": a.collisions}])
            return 0
        finally:
            shutil.rmtree(work, ignore_errors=True)


# -- type libraries ---------------------------------------------------------------------------------


def store_til(til: Any, path: Path) -> bool:
    """Write a type library; the kernel honours only an absolute file name
    with no directory argument."""
    import ida_typeinf

    return bool(ida_typeinf.store_til(til, None, str(path))) and path.exists()


def til_files() -> list[Path]:
    out: list[Path] = []
    for base in (idausr() / "til", (idadir() or Path("/nonexistent")) / "til"):
        if base.is_dir():
            out.extend(sorted(base.rglob("*.til")))
    return out


@register
class Til(Command):
    name = "til"
    group = "knowledge"
    summary = "type libraries: list, dump, make, merge, export"
    target = "optional"
    subcommands = {"list": "available .til files", "dump": "print a type library as C",
                   "make": "build a .til from headers", "merge": "merge type libraries",
                   "export": "local types of a database as a .til"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        if sub in ("make", "merge", "export"):
            p.add_argument("-o", dest="output", required=True, metavar="OUT.til")
        if sub == "make":
            p.add_argument("--target", metavar="TRIPLE")
            p.add_argument("-I", dest="include", action="append", default=[], metavar="DIR")
            p.add_argument("-D", dest="define", action="append", default=[], metavar="NAME[=VALUE]")
            p.add_argument("--description", metavar="TEXT")

    def run(self, inv: Invocation) -> int:
        sub = inv.args.sub
        a = inv.args
        if sub == "list":
            out = [{"_t": "til", "name": p.stem, "processor": p.parent.name, "path": str(p)} for p in til_files()]
            inv.emit(out)
            return 0
        if sub == "export":
            inv.positionals(0)
            out = Path(a.output).expanduser().resolve()
            inv.call("til.export", {"path": str(out)})
            return 0
        from .. import local

        with local.scratch_database():
            return self._offline(inv, sub)

    def _offline(self, inv: Invocation, sub: str) -> int:
        import ida_typeinf

        a = inv.args
        if sub == "dump":
            if not a.items:
                raise usage("icli til dump: expected FILE.til [name...]")
            path = _need_file(a.items[0]) if Path(a.items[0]).exists() else a.items[0]
            til = ida_typeinf.load_til(str(path))
            if til is None:
                raise IdaxError(Exit.NOT_FOUND, f"{a.items[0]}: cannot load type library", "NOTFOUND")
            names = a.items[1:] or list(til.type_names)
            parts = []
            for n in names:
                tif = ida_typeinf.tinfo_t()
                if not tif.get_named_type(til, n):
                    raise IdaxError(Exit.EMPTY_SELECTION, f"{a.items[0]}: no type {n!r}", "NOMATCH")
                flags = ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI | \
                    ida_typeinf.PRTYPE_DEF
                parts.append(tif._print(n, flags) or f"/* {n} */")
            text = "\n\n".join(parts) + "\n"
            if inv.emitter.format in ("text", "raw"):
                inv.emitter.raw([text])
            else:
                inv.emit([{"_t": "header", "til": str(path), "types": len(names), "text": text}])
            return 0
        if sub == "make":
            out = Path(a.output).expanduser().resolve()
            headers = [_need_file(h) for h in a.items]
            if not headers:
                raise usage("icli til make: expected header file(s)")
            import ida_srclang

            til = ida_typeinf.new_til(out.name, a.description or out.stem)
            args = [f"-I{Path(d).resolve()}" for d in a.include] + [f"-D{d}" for d in a.define]
            if a.target:
                args.append(f"-target {a.target}")
            ida_srclang.set_parser_argv("clang", " ".join(args))
            errors = 0
            for h in headers:
                n = ida_srclang.parse_decls_with_parser("clang", til, str(h), True)
                if n < 0:
                    n = ida_typeinf.parse_decls(til, str(h), None, ida_typeinf.HTI_FIL)
                errors += max(n, 0)
            if errors:
                raise IdaxError(Exit.USAGE, f"{errors} error(s) parsing headers", "BADDECL")
            ida_typeinf.compact_til(til)
            if not store_til(til, out):
                raise IdaxError(Exit.INTERNAL, f"{out}: cannot write", "INTERR")
            inv.emit([{"_t": "til", "path": str(out), "types": len(list(til.type_names))}])
            return 0
        if sub == "merge":
            out = Path(a.output).expanduser().resolve()
            if not a.items:
                raise usage("icli til merge: expected input .til files")
            merged = ida_typeinf.new_til(out.name, f"merge of {', '.join(Path(x).name for x in a.items)}")
            ida_typeinf.enable_numbered_types(merged, True)  # copy_named_type needs ordinals
            count = 0
            for x in a.items:
                src = ida_typeinf.load_til(str(_need_file(x)))
                if src is None:
                    raise IdaxError(Exit.NOT_FOUND, f"{x}: cannot load type library", "NOTFOUND")
                for n in src.type_names:
                    if ida_typeinf.copy_named_type(merged, src, n):
                        count += 1
            ida_typeinf.compact_til(merged)
            if not store_til(merged, out):
                raise IdaxError(Exit.INTERNAL, f"{out}: cannot write", "INTERR")
            inv.emit([{"_t": "til", "path": str(out), "types": count}])
            return 0
        raise usage(f"icli til: unknown subcommand {sub}")


# -- Lumina -----------------------------------------------------------------------------------------


@register
class Lumina(Edit):
    name = "lumina"
    group = "knowledge"
    summary = "Lumina: pull (and --apply), push, del, history"
    subcommands = {"pull": "fetch metadata for functions", "push": "push user-named functions",
                   "del": "delete own metadata", "history": "a function's metadata history"}

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")

    def configure_sub(self, sub: str, p: argparse.ArgumentParser) -> None:
        p.add_argument("items", nargs="*")
        p.add_argument("--server", metavar="HOST:PORT")
        if sub == "pull":
            p.add_argument("--apply", action="store_true")

    def run(self, inv: Invocation) -> int:
        sub = inv.args.sub
        rest = inv.positionals(0)
        if inv.args.server:
            host, _, port = inv.args.server.rpartition(":")
            inv.g.set += [f"LUMINA_HOST=\"{host}\"", f"LUMINA_PORT={port}"]
        sels = inv.selectors(rest) if rest else None
        if sub in ("del", "history") and not sels:
            raise usage(f"icli lumina {sub}: expected selector(s)")
        params: dict[str, Any] = {"selectors": sels}
        if sub == "pull":
            params["apply"] = inv.args.apply
        return self.call(inv, f"lumina.{sub}", params)


# -- load ------------------------------------------------------------------------------------------------

LOAD_KINDS = ("pdb", "dwarf", "svd", "map", "idc", "names", "coverage", "binary", "snapshot")


def parse_names(text: str) -> list[dict]:
    """address,name CSV / TSV, or 'address name' lines."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        parts = [p for p in re.split(r"[,\t ]+", s) if p]
        if len(parts) < 2:
            raise usage(f"names:{i}: expected 'address name'")
        a, n = (parts[0], parts[1]) if parse_address_number(parts[0]) is not None or parts[0].isdigit() else (
            parts[1], parts[0])
        ea = parse_address_number(a)
        if ea is None:
            ea = int(a, 16) if re.fullmatch(r"[0-9a-fA-F]+", a) else None
        if ea is None:
            raise usage(f"names:{i}: bad address {a!r}")
        out.append({"ea": ea, "name": n})
    return out


_MSVC_PUBLIC = re.compile(r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s")
_GNU_PUBLIC = re.compile(r"^\s+0x([0-9a-fA-F]{8,16})\s+([A-Za-z_.$][\w.$@]*)\s*$")


def parse_map(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _MSVC_PUBLIC.match(line)
        if m:
            out.append({"ea": int(m.group(2), 16), "name": m.group(1)})
            continue
        m = _GNU_PUBLIC.match(line)
        if m:
            out.append({"ea": int(m.group(1), 16), "name": m.group(2)})
    return out


def parse_coverage(path: Path, base: int | None = None) -> list[dict]:
    """drcov (module-relative basic blocks) or lighthouse-style text
    (module+offset or absolute addresses, one per line)."""
    data = path.read_bytes()
    out: list[dict] = []
    if data.startswith(b"DRCOV VERSION"):
        text_end = data.find(b"BB Table:")
        header = data[:text_end].decode("latin-1")
        rest = data[text_end:]
        line_end = rest.find(b"\n")
        m = re.match(rb"BB Table:\s*(\d+)", rest)
        n = int(m.group(1)) if m else 0
        bbs = rest[line_end + 1:]
        mods = {}
        for ln in header.splitlines():
            cols = [c.strip() for c in ln.split(",")]
            if cols and cols[0].isdigit() and len(cols) >= 3:
                mods[int(cols[0])] = cols[-1]
        if bbs[:2].isascii() and bbs.lstrip().startswith(b"module["):
            for ln in bbs.decode("latin-1").splitlines():
                m2 = re.match(r"module\[\s*(\d+)\]:\s*0x([0-9a-fA-F]+),\s*(\d+)", ln)
                if m2:
                    out.append({"rva": int(m2.group(2), 16), "hits": 1, "module": mods.get(int(m2.group(1)))})
        else:
            for i in range(n):
                start, size, mod = struct.unpack_from("<IHH", bbs, i * 8)
                out.append({"rva": start, "hits": 1, "module": mods.get(mod), "size": size})
        return out
    for ln in data.decode("latin-1").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(?:(\S+?)\+)?(0x[0-9a-fA-F]+|[0-9a-fA-F]+)(?:\s+(\d+))?$", s)
        if not m:
            continue
        v = int(m.group(2), 16)
        hits = int(m.group(3)) if m.group(3) else 1
        out.append({"rva" if m.group(1) else "ea": v, "hits": hits})
    return out


@register
class Load(Edit):
    name = "load"
    group = "knowledge"
    summary = "add data to a database: pdb, dwarf, svd, map, idc, names, coverage, binary, snapshot"
    rest_min = 1

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("kind", choices=LOAD_KINDS, metavar="kind")
        super().configure(p)
        p.add_argument("--at", metavar="ADDR", help="address for binary/snapshot")
        p.add_argument("--name", dest="seg_name", metavar="SEGMENT", help="segment name for binary")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        rest = inv.positionals()
        if len(rest) != 1:
            raise usage(f"icli load {a.kind}: expected one file")
        path = _need_file(rest[0])
        params: dict[str, Any] = {"kind": a.kind, "path": str(path)}
        if a.kind in ("names", "map"):
            text = path.read_text(errors="replace")
            records = parse_names(text) if a.kind == "names" else parse_map(text)
            if not records:
                raise usage(f"{rest[0]}: no names found")
            params["records"] = records
        elif a.kind == "coverage":
            recs = parse_coverage(path)
            if not recs:
                raise usage(f"{rest[0]}: no coverage records found")
            params["records"] = recs
        elif a.kind in ("binary", "snapshot"):
            if not a.at:
                raise usage(f"icli load {a.kind}: --at ADDR is required")
            params["at"] = parse_int(a.at)
            params["name"] = a.seg_name
        return self.call(inv, "load", params)
