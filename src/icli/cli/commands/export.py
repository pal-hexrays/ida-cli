"""export: produce a file from the database (standard output by default)."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

from ...errors import Exit, IdaxError, usage
from ...lang import template as tmpl
from ..registry import Command, Invocation, register

FORMATS = ("i64", "asm", "lst", "html", "map", "idc", "python", "journal", "dif", "exe", "bin", "c", "cpp", "mc",
           "h", "til", "sig", "pat", "dot", "gdl", "svg", "sqlite", "sarif")
SELECTABLE = {"i64", "asm", "lst", "html", "bin", "c", "cpp", "mc", "sig", "pat", "dot", "gdl", "svg", "sarif"}
BINARY = {"i64", "exe", "bin", "til", "sqlite", "sig"}
SQL_KINDS = ["functions", "names", "strings", "imports", "exports", "entries", "segments", "xrefs", "types",
             "comments", "bookmarks", "tags", "problems", "fixups", "blocks", "patches", "switches"]


@register
class Export(Command):
    name = "export"
    group = "output"
    summary = "produce a file (format named explicitly) from the database"
    overrides = frozenset({"--demangle"})

    def configure(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("export_format", choices=FORMATS, metavar="format")
        p.add_argument("items", nargs="*", metavar="target/selector")
        p.add_argument("-o", dest="output", metavar="PATH", help="output path (templates allowed)")
        p.add_argument("--with-types", action="store_true")
        p.add_argument("--maturity", default="lvars", metavar="LEVEL")
        p.add_argument("--graph", default="calls", choices=("calls", "flow", "xrefs"))
        p.add_argument("--segments", action="store_true")
        p.add_argument("--demangle", dest="map_demangle", action="store_true")
        p.add_argument("--locals", action="store_true")
        p.add_argument("--highlight", metavar="RECORDS.jsonl", help="records whose addresses are highlighted")
        p.add_argument("--in-place", action="store_true")
        p.add_argument("--force", action="store_true")
        p.add_argument("--library-name", metavar="TEXT")

    def run(self, inv: Invocation) -> int:
        a = inv.args
        fmt = a.export_format
        rest = inv.positionals(0)
        if rest and fmt not in SELECTABLE:
            raise usage(f"export {fmt} writes the whole database; it takes no selector")
        if a.in_place and (fmt != "exe" or not a.force):
            raise usage("--in-place is for export exe and needs --force")
        out = a.output
        per_item = bool(out) and tmpl.has_placeholders(out)
        if per_item and fmt not in ("c", "cpp", "mc", "asm", "lst", "html"):
            raise usage(f"export {fmt}: per-item -o templates are not supported for this format")
        sels = inv.selectors(rest) if rest else None
        if out and not per_item:
            inv.check_output(Path(out).expanduser())
        if fmt == "sqlite":
            return self._sqlite(inv, out, sels)
        if fmt == "i64":
            return self._i64(inv, out, sels)
        if fmt == "sig":
            return self._sig(inv, out, sels)
        highlight = self._highlight(a.highlight) if a.highlight else None
        params: dict[str, Any] = {
            "format": fmt, "selectors": sels, "with_types": a.with_types, "maturity": a.maturity,
            "graph": a.graph, "segments": a.segments, "demangle": a.map_demangle, "locals": a.locals,
            "highlight": highlight, "in_place": a.in_place,
            "path": None if (out is None or per_item) else str(Path(out).expanduser().resolve()),
            "path_template": str(Path(out).expanduser().absolute()) if per_item else None,
        }
        res = inv.call("export", params, emit=False)
        if out is None:
            if res.get("extra", {}).get("binary"):
                sys.stdout.buffer.write(bytes.fromhex(res["extra"]["binary"]))
            else:
                for chunk in res.get("raw", []):
                    sys.stdout.write(chunk)
            sys.stdout.flush()
            return 0
        if not inv.g.output.quiet or inv.emitter.format != "text":
            inv.emit(res.get("records", []))
        return 0

    @staticmethod
    def _highlight(path: str) -> list[int]:
        from ...lang.values import parse_address_number

        out = []
        for line in Path(path).read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            for k in ("ea", "start", "from"):
                v = rec.get(k)
                if isinstance(v, str) and parse_address_number(v) is not None:
                    out.append(parse_address_number(v))
                    break
        return out

    def _sqlite(self, inv: Invocation, out: str | None, sels: Any) -> int:
        if not out:
            raise usage("export sqlite needs -o FILE")
        path = Path(out).expanduser().resolve()
        if path.exists():
            path.unlink()
        conn = sqlite3.connect(path)
        total = 0
        for kind in SQL_KINDS:
            res = inv.call("list", {"kind": kind}, emit=False, ctx={"fields": None})
            rows = [{k: v for k, v in r.items() if k != "_t"} for r in res.get("records", [])]
            cols: list[str] = []
            for r in rows:
                for k in r:
                    if k not in cols:
                        cols.append(k)
            if not cols:
                cols = ["ea"]
            conn.execute(f'CREATE TABLE "{kind}" ({", ".join(chr(34) + c + chr(34) for c in cols)})')
            conn.executemany(
                f'INSERT INTO "{kind}" VALUES ({", ".join("?" for _ in cols)})',
                [[json.dumps(r.get(c)) if isinstance(r.get(c), (list, dict)) else r.get(c) for c in cols]
                 for r in rows])
            total += len(rows)
        # function metrics used by the manual's examples (callers = 0)
        res = inv.call("list", {"kind": "functions"}, emit=False,
                       ctx={"fields": ["ea", "name", "size", "callers", "callees", "xrefs_to", "lib", "thunk"]})
        conn.execute('DROP TABLE "functions"')
        conn.execute('CREATE TABLE "functions" (ea, name, size, callers, callees, xrefs_to, lib, thunk)')
        conn.executemany('INSERT INTO "functions" VALUES (?,?,?,?,?,?,?,?)',
                         [[r.get(c) for c in ("ea", "name", "size", "callers", "callees", "xrefs_to", "lib", "thunk")]
                          for r in res.get("records", [])])
        conn.commit()
        conn.close()
        inv.emit([{"_t": "export", "format": "sqlite", "path": str(path), "rows": total, "tables": len(SQL_KINDS)}])
        return 0

    def _sig(self, inv: Invocation, out: str | None, sels: Any) -> int:
        from .knowledge import _flair, sig_header

        if not out:
            raise usage("export sig needs -o FILE.sig")
        path = Path(out).expanduser().resolve()
        res = inv.call("export", {"format": "pat", "selectors": sels, "path": None}, emit=False)
        work = Path(tempfile.mkdtemp(prefix="icli-sig-"))
        try:
            pat = work / "export.pat"
            pat.write_text("".join(res.get("raw", [])))
            import subprocess

            name = inv.args.library_name or path.stem
            r = subprocess.run([str(_flair("sigmake")), f"-n{name}", str(pat), str(path)], capture_output=True,
                               text=True, cwd=work)
            if not path.exists():
                exc = path.with_suffix(".exc")
                if exc.exists():
                    exc.unlink()
                    raise IdaxError(Exit.CONFLICT, "pattern collisions (use icli sig make --collisions)", "CONFLICT")
                raise IdaxError(Exit.LOAD, f"sigmake failed: {(r.stderr or r.stdout)[-500:]}", "FLAIR")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        h = sig_header(path)
        inv.emit([{"_t": "export", "format": "sig", "path": str(path), "functions": h.get("functions")}])
        return 0

    def _i64(self, inv: Invocation, out: str | None, sels: Any) -> int:
        if not out:
            raise usage("export i64 needs -o FILE.i64")
        dst = Path(out).expanduser().resolve()
        session = inv.open()
        if not sels:
            session.ensure("analyzed")
            session.save()
            shutil.copy2(session.target.db, dst)
            inv.emit([{"_t": "export", "format": "i64", "path": str(dst), "size": dst.stat().st_size}])
            return 0
        return self._minimal(inv, dst, sels)

    def _minimal(self, inv: Invocation, dst: Path, sels: Any) -> int:
        """A minimal database holding only the selected functions, their
        callees' prototypes and the types they use."""
        from ..opening import open_session
        from ..options import GlobalOptions

        spec = inv.call("export.minimal", {"selectors": sels}, emit=False)["records"][0]
        work = Path(tempfile.mkdtemp(prefix="icli-min-"))
        try:
            regions = sorted(spec["regions"], key=lambda r: r["start"])
            merged: list[dict] = []
            for r in regions:
                if merged and r["start"] <= merged[-1]["end"]:
                    last = merged[-1]
                    data = bytes.fromhex(last["bytes"])
                    extra = bytes.fromhex(r["bytes"])[max(0, last["end"] - r["start"]):]
                    last["bytes"] = (data + extra).hex()
                    last["end"] = max(last["end"], r["end"])
                else:
                    merged.append(dict(r))
            blob = work / "code.bin"
            segments = []
            offset = 0
            with blob.open("wb") as fh:
                for i, r in enumerate(merged):
                    data = bytes.fromhex(r["bytes"])
                    fh.write(data)
                    segments.append(f"code{i}={r['start']:#x}-{r['end']:#x}:CODE:rx@{blob}:{offset}")
                    offset += len(data)
            covered = [(r["start"], r["end"]) for r in merged]
            for n in spec["names"]:
                ea = n["ea"]
                if not any(s <= ea < e for s, e in covered):
                    segments.append(f"ext_{ea:x}={ea:#x}-{ea + 1:#x}:XTRN:r")
                    covered.append((ea, ea + 1))
            seed = work / "seed.bin"
            seed.write_bytes(b"\0")
            g = GlobalOptions()
            g.db = str(dst)
            g.output.quiet = True
            g.load = {"loader": "binary", "processor": spec["processor"], "bitness": spec["bitness"],
                      "segment": segments, "base": 0}
            if dst.exists():
                dst.unlink()
            s = open_session(str(seed), g, inv.emitter.diag)
            try:
                s.call("export.minimal.apply", {"spec": spec}, need="analyzed")
            finally:
                s.close(save=True)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        inv.emit([{"_t": "export", "format": "i64", "path": str(dst), "functions": len(spec["functions"]),
                   "callees": len(spec["names"]), "types": len(spec["types"])}])
        return 0
