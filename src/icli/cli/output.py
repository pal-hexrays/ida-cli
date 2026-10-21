"""Stream output: text, json, jsonl, csv, tsv, raw and templates
(OUTPUT FORMATS in icli(1)).  Diagnostics never go to standard output."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, TextIO

from ..lang import template as tmpl

FORMATS = ("text", "json", "jsonl", "csv", "tsv", "raw")


@dataclass
class OutputOptions:
    format: str | None = None
    template: str | None = None
    header: str | None = None
    footer: str | None = None
    fields: list[str] | None = None
    no_header: bool = False
    null: bool = False
    color: str = "auto"
    quiet: bool = False
    verbose: int = 0


def default_format(stream: TextIO | None = None) -> str:
    stream = stream or sys.stdout
    try:
        return "text" if stream.isatty() else "jsonl"
    except (AttributeError, ValueError):
        return "jsonl"


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        if all(not isinstance(x, (dict, list)) for x in v):
            return ",".join(_cell(x) for x in v)
        return json.dumps(v, separators=(",", ":"))
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


def _flatten(rec: dict, prefix: str = "") -> dict:
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if isinstance(v, dict) and v and not prefix.count("."):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


@dataclass
class Emitter:
    opts: OutputOptions
    out: TextIO = field(default_factory=lambda: sys.stdout)
    err: TextIO = field(default_factory=lambda: sys.stderr)
    raw_field: str | None = None
    schema: str | None = None
    database: dict | None = None
    tag: dict | None = None      # fields merged into every record (batch: {"step": n})
    extra: dict | None = None    # top-level fields of the -f json document

    def __post_init__(self) -> None:
        self.format = self.opts.format or default_format(self.out)
        self.count = 0
        self._buffer: list[dict] = []
        self._warnings: list[dict] = []
        self._csv_header: list[str] | None = None
        self._template = tmpl.parse(self.opts.template) if self.opts.template else None
        self._header_done = False
        self.end = "\0" if self.opts.null else "\n"

    def use_template(self, text: str) -> None:
        """Render records through ``text`` (commands with a natural text form)."""
        self.opts.template = text
        self._template = tmpl.parse(text)

    # -- fields --------------------------------------------------------------------

    def wanted_fields(self) -> list[str] | None:
        """Fields the engine must compute: --fields, else those of -t."""
        if self.opts.fields:
            return list(self.opts.fields)
        if self._template is not None:
            names = list(self._template.fields)
            for extra in (self.opts.header, self.opts.footer):
                if extra:
                    names += [n for n in tmpl.parse(extra).fields if n not in ("count",)]
            return names
        return None

    def _project(self, rec: dict) -> dict:
        if not self.opts.fields:
            return rec
        out = {"_t": rec["_t"]} if "_t" in rec and self.format in ("json", "jsonl") else {}
        for f in self.opts.fields:
            out[f] = tmpl.lookup(rec, f)
        return out

    # -- records -------------------------------------------------------------------

    def emit(self, records: list[dict]) -> None:
        for rec in records:
            self.count += 1
            if self.tag:
                rec = {**rec, **self.tag}
            rec = self._project(rec)
            if self._template is not None:
                self._write_header()
                text = self._template.render(rec)
                if self.opts.null and text.endswith("\n"):
                    text = text[:-1] + "\0"
                self.out.write(text)
            elif self.format == "jsonl":
                self.out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + self.end)
            elif self.format in ("csv", "tsv"):
                self._write_csv(rec)
            elif self.format == "raw":
                self._write_raw(rec)
            else:
                self._buffer.append(rec)
        self.out.flush()

    def raw(self, chunks: list[str]) -> None:
        """Natural payload produced by the engine (e.g. an export to stdout)."""
        for c in chunks:
            self.out.write(c)
            if not c.endswith("\n"):
                self.out.write("\n")
        self.out.flush()

    def _write_header(self) -> None:
        if not self._header_done:
            self._header_done = True
            if self.opts.header and not self.opts.no_header:
                self.out.write(tmpl.parse(self.opts.header, record_newline=False).render({}))

    def _write_raw(self, rec: dict) -> None:
        if self.raw_field and self.raw_field in rec and rec[self.raw_field] is not None:
            text = rec[self.raw_field]
            if not isinstance(text, str):
                text = _cell(text)
            self.out.write(text if text.endswith("\n") else text + self.end)
        else:
            self.out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + self.end)

    def _write_csv(self, rec: dict) -> None:
        rec = {k: v for k, v in rec.items() if k != "_t"}
        if self._csv_header is None:
            self._csv_header = list(rec)
            if not self.opts.no_header:
                self._csv_row(self._csv_header)
        for k in rec:
            if k not in self._csv_header:
                self._csv_header.append(k)
        self._csv_row([_cell(rec.get(k)) for k in self._csv_header])

    def _csv_row(self, cells: list[str]) -> None:
        buf = io.StringIO()
        if self.format == "csv":
            csv.writer(buf, lineterminator=self.end).writerow(cells)
        else:
            buf.write("\t".join(c.replace("\t", " ").replace("\n", " ") for c in cells) + self.end)
        self.out.write(buf.getvalue())

    # -- diagnostics -----------------------------------------------------------------

    def diag(self, level: str, code: str, msg: str) -> None:
        if level in ("info", "progress") and self.opts.quiet:
            return
        if level == "warning":
            self._warnings.append({"_t": "diag", "level": level, "code": code, "msg": msg})
        if self.format in ("json", "jsonl") and not self._template:
            self.err.write(json.dumps({"_t": "diag", "level": level, "code": code, "msg": msg}) + "\n")
        else:
            prefix = "" if level == "info" else f"{level}: "
            self.err.write(f"icli: {prefix}{msg}\n")
        self.err.flush()

    # -- finish ------------------------------------------------------------------------

    def close(self) -> None:
        if self._template is not None:
            self._write_header()
            if self.opts.footer and not self.opts.no_header:
                self.out.write(tmpl.parse(self.opts.footer, record_newline=False).render({"count": self.count}))
        elif self.format == "json":
            doc: dict[str, Any] = {}
            schema = self.schema or (self._buffer[0].get("_t") if self._buffer else None)
            if schema:
                doc["schema"] = f"icli.{schema}/1" if "/" not in schema else schema
            if self.database:
                doc["database"] = self.database
            doc["records"] = self._buffer
            doc["warnings"] = self._warnings
            if self.extra:
                doc.update(self.extra)
            self.out.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        elif self.format == "text":
            self._write_text(self._buffer)
        self._buffer = []
        try:
            self.out.flush()
        except (BrokenPipeError, ValueError):
            pass

    def _write_text(self, records: list[dict]) -> None:
        if not records:
            return
        color = self._color()

        def wide(rec: dict) -> bool:
            return len(rec) > 9 or any(isinstance(v, list) and v and isinstance(v[0], dict) for v in rec.values())

        if (len(records) == 1 and len(records[0]) > 6) or any(wide(r) for r in records):
            for i, rec in enumerate(records):
                if i:
                    self.out.write(self.end)
                flat = _flatten({k: v for k, v in rec.items() if k != "_t"})
                width = max(len(k) for k in flat) if flat else 0
                for k, v in flat.items():
                    key = f"\x1b[1m{k:<{width}}\x1b[0m" if color else f"{k:<{width}}"
                    self.out.write(f"{key}  {_cell(v)}{self.end}")
            return
        # group consecutive records with the same shape
        groups: list[list[dict]] = []
        for rec in records:
            if groups and list(groups[-1][0]) == list(rec):
                groups[-1].append(rec)
            else:
                groups.append([rec])
        for gi, group in enumerate(groups):
            cols = [k for k in group[0] if k != "_t"]
            multiline = [c for c in cols if any("\n" in _cell(r.get(c)) for r in group)]
            if multiline:
                for r in group:
                    head = "  ".join(_cell(r.get(c)) for c in cols if c not in multiline)
                    if head:
                        self.out.write(head + self.end)
                    for c in multiline:
                        self.out.write(_cell(r.get(c)) + self.end)
                continue
            rows = [[_cell(r.get(c)) for c in cols] for r in group]
            widths = [max([len(c)] + [len(row[i]) for row in rows]) for i, c in enumerate(cols)]
            if gi:
                self.out.write(self.end)
            if not self.opts.no_header:
                line = "  ".join(c.upper().ljust(w) for c, w in zip(cols, widths)).rstrip()
                self.out.write((f"\x1b[1m{line}\x1b[0m" if color else line) + self.end)
            for row in rows:
                cells = []
                for i, (cell, w) in enumerate(zip(row, widths)):
                    numeric = cell.isdigit() and i
                    cells.append(cell.rjust(w) if numeric else cell.ljust(w))
                self.out.write("  ".join(cells).rstrip() + self.end)

    def _color(self) -> bool:
        if self.opts.color == "never" or os.environ.get("NO_COLOR"):
            return False
        if self.opts.color == "always":
            return True
        try:
            return self.out.isatty()
        except (AttributeError, ValueError):
            return False
