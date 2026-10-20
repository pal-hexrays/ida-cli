"""JSON Schema of the records commands emit (``icli schema``).

Item kinds are read from the engine sources with :mod:`ast` (their
``f_<field>`` methods and return annotations are the single source of
truth), so no IDA module is imported.  Records that are not item kinds
(edits, diffs, journal entries, ...) are declared here."""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

ENGINE_KINDS = Path(__file__).resolve().parents[1] / "engine" / "kinds"

_ANNOTATION_TYPES = {
    "int": "integer", "float": "number", "bool": "boolean", "str": "string", "list": "array", "dict": "object",
}
ADDRESS = {"type": ["string", "null"], "description": "address, formatted per --addr (0x401000)"}

# Records produced by operations rather than item kinds.
RECORDS: dict[str, dict[str, str]] = {
    "edit": {"kind": "string", "ea": "address", "key": "any", "before": "any", "after": "any",
             "status": "string", "rev": "integer", "name": "string", "comment": "string", "type": "string",
             "tags": "array", "undo_of": "integer"},
    "journal": {"rev": "integer", "time": "string", "author": "string", "command": "string", "kind": "string",
                "ea": "address", "key": "any", "before": "any", "after": "any", "message": "string",
                "rva": "string", "func": "string", "func_hash": "string", "func_off": "string"},
    "diff": {"diff": "string", "similarity": "number", "ea": "address", "other_ea": "address", "name": "string",
             "other_name": "string", "changed_blocks": "integer", "round": "string", "patch": "string"},
    "pseudocode": {"ea": "address", "name": "string", "status": "string", "pseudocode": "string",
                   "hexrays_err": "integer", "hexrays_msg": "string", "err_ea": "address", "lines": "array",
                   "lvars": "array", "ctree": "object"},
    "pseudocode_line": {"ea": "address", "func": "string", "line": "integer", "text": "string", "status": "string"},
    "insn": {"ea": "address", "size": "integer", "bytes": "string", "mnem": "string", "operands": "array",
             "text": "string", "line": "string"},
    "call": {"from": "address", "to": "address", "caller": "string", "callee": "string", "depth": "integer"},
    "match": {"ea": "address", "name": "string", "func": "string", "text": "string", "disasm": "string",
              "line": "integer"},
    "crypto": {"ea": "address", "name": "string", "size": "integer", "label": "string", "refs": "array",
               "func": "string"},
    "info": {"input": "string", "db": "string", "size": "integer", "md5": "string", "sha256": "string",
             "loader": "string", "processor": "string", "bitness": "integer", "endian": "string",
             "compiler": "object", "image_base": "address", "entry": "address", "entries": "array",
             "counts": "object", "signatures": "array", "tils": "array", "debug_info": "array", "state": "string",
             "passes": "array", "kernel": "string", "cache_key": "string"},
    "status": {"state": "string", "passes": "array", "auto_is_ok": "boolean", "pending": "object",
               "journal": "integer", "revision": "integer", "lock": "object", "db": "string"},
    "identify": {"path": "string", "loader": "string", "loaders": "array", "format": "string", "arch": "string",
                 "bitness": "integer", "endian": "string", "compiler": "string", "packer": "string",
                 "size": "integer", "entropy": "number", "sections": "array", "md5": "string", "sha1": "string",
                 "sha256": "string", "imphash": "string", "tlsh": "string", "ssdeep": "string", "pdb": "object",
                 "build_id": "string", "signed": "boolean", "signer": "string", "n_imports": "integer",
                 "n_exports": "integer"},
    "item": {"ea": "address", "segment": "string", "item": "string", "size": "integer", "flags": "array",
             "name": "string", "func": "string", "comments": "object", "disasm": "string", "type": "string",
             "xrefs_to": "array", "xrefs_from": "array", "operands": "array", "function": "object"},
    "export": {"format": "string", "path": "string", "size": "integer"},
    "result": {}, "value": {"value": "any"}, "count": {"kind": "string", "count": "integer"},
    "assert": {"count": "integer", "cond": "string", "ok": "boolean"},
    "ref": {"symbol": "string", "kind": "string", "signature": "string", "doc": "string", "example": "string",
            "source": "string"},
    "loader": {"file": "string", "rank": "integer", "loader": "string", "format": "string", "processor": "string"},
    "processor": {"module": "string", "family": "string", "variants": "array", "decompiler": "string",
                  "assembler": "boolean"},
    "lumina": {"ea": "address", "name": "string", "type": "string", "score": "number", "applied": "boolean"},
}

COMMAND_RECORDS = {
    "info": ["info"], "status": ["status"], "identify": ["identify"], "loaders": ["loader"],
    "processors": ["processor"], "analyze": ["analysis"], "show": ["item"], "disasm": ["insn"],
    "decompile": ["pseudocode", "pseudocode_line"], "xrefs": ["xref"], "callgraph": ["call"],
    "search": ["match", "string", "crypto"], "resolve": ["address"], "rename": ["edit"], "comment": ["edit"],
    "type": ["edit", "type"], "func": ["edit"], "make": ["edit"], "patch": ["edit"], "tag": ["edit"],
    "apply": ["edit"], "log": ["journal"], "undo": ["edit"], "diff": ["diff"], "port": ["edit"],
    "export": ["export"], "exec": ["result", "value"], "ref": ["ref"], "assert": ["assert"],
    "lumina": ["lumina", "edit"], "sig": ["sig", "edit"], "load": ["edit", "load"],
}


@lru_cache(maxsize=1)
def kinds() -> dict[str, dict]:
    """record name -> {"plural", "defaults", "fields": {name: json type}} from the engine sources."""
    classes: dict[str, dict] = {}
    for path in sorted(ENGINE_KINDS.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            info: dict = {"bases": [b.id for b in node.bases if isinstance(b, ast.Name)], "fields": {},
                          "record": None, "plural": None, "defaults": None}
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    key = stmt.targets[0].id
                    if key in ("record", "plural", "name", "defaults"):
                        try:
                            info[key] = ast.literal_eval(stmt.value)
                        except ValueError:
                            pass
                elif isinstance(stmt, ast.FunctionDef) and stmt.name.startswith("f_"):
                    info["fields"][stmt.name[2:]] = _json_type(stmt.returns)
            classes[node.name] = info

    def resolve(name: str) -> dict:
        info = classes[name]
        fields: dict[str, str] = {}
        defaults = info["defaults"]
        record = info["record"]
        plural = info["plural"]
        for b in info["bases"]:
            if b in classes:
                parent = resolve(b)
                fields.update(parent["fields"])
                defaults = defaults or parent["defaults"]
        fields.update(info["fields"])
        return {"fields": fields, "defaults": defaults, "record": record, "plural": plural}

    out = {}
    for name, info in classes.items():
        r = resolve(name)
        if r["record"]:
            out[r["record"]] = r
    return out


def _json_type(node: ast.expr | None) -> str:
    if node is None:
        return "any"
    text = ast.unparse(node)
    if text in ("Any", "object") or "Addr" in text:
        return "address" if text != "object" else "any"
    for py, js in _ANNOTATION_TYPES.items():
        if text.startswith(py):
            return js
    return "any"


def _property(t: str) -> dict:
    if t == "address":
        return dict(ADDRESS)
    if t == "any":
        return {}
    return {"type": [t, "null"]}


def schema_for(record: str, version: int = 1) -> dict:
    k = kinds().get(record)
    fields = dict(k["fields"]) if k else dict(RECORDS.get(record, {}))
    for common in ("index", "count"):
        fields.setdefault(common, "integer")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"icli.{record}/{version}",
        "title": f"icli {record} record",
        "type": "object",
        "properties": {"_t": {"const": record}, **{f: _property(t) for f, t in sorted(fields.items())}},
        "required": ["_t"],
        "x-default-fields": k["defaults"] if k else None,
    }


def records_for_command(command: str, kind: str | None = None) -> list[str]:
    if command == "list":
        if kind is None:
            return sorted({v["record"] for v in kinds().values() if v.get("plural")})
        for rec, v in kinds().items():
            if kind in (rec, v.get("plural")):
                return [rec]
        return []
    return COMMAND_RECORDS.get(command, [])
