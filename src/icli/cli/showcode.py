"""``--show-code``: the ida-domain Python a command is equivalent to.

Common commands get idiomatic ida-domain code with selectors expanded into
explicit loops and filters; every other command prints the exact engine
call, which runs unchanged under ``icli exec``.
"""

from __future__ import annotations

import json
from typing import Any

from ..lang import selector as psel


def _sel_expr(nodes: list[dict] | None) -> str | None:
    """A Python expression yielding func_t objects for simple selectors."""
    if not nodes or len(nodes) != 1:
        return None
    n = nodes[0]
    if n["op"] == "typed" and n["type"] == "func":
        if n["pattern"] in ("*", ""):
            return "db.functions"
        if n["regex"]:
            return (f"(f for f in db.functions if re.search({n['pattern']!r}, db.functions.get_name(f)"
                    f"{', re.I' if 'i' in n.get('flags', '') else ''}))")
        return f"(f for f in db.functions if fnmatch.fnmatchcase(db.functions.get_name(f), {n['pattern']!r}))"
    if n["op"] == "addr" and len(n["expr"]["terms"]) == 1:
        a = n["expr"]["terms"][0][1]
        if "name" in a:
            return f"[db.functions.get_function_by_name({a['name']!r})]"
        if "num" in a and "seg" not in a:
            return f"[db.functions.get_at({a['num']:#x})]"
    return None


def _predicate(text: str | None) -> str | None:
    if not text:
        return None
    from ..lang import expr

    tree = expr.parse(text)
    # ida-domain hands out func_t objects: size() is a method
    simple = {"size": "f.size()", "name": "db.functions.get_name(f)", "ea": "f.start_ea",
              "end": "f.end_ea"}

    def emit(node: Any) -> str | None:
        if node.kind == "lit":
            return repr(node.value)
        if node.kind == "field":
            return simple.get(node.value)
        if node.kind == "not":
            inner = emit(node.left)
            return f"not ({inner})" if inner else None
        left, right = emit(node.left), emit(node.right)
        if left is None or right is None:
            return None
        op = {"&&": "and", "||": "or"}.get(node.value, node.value)
        if op == "~":
            return f"re.search({right}, str({left}))"
        return f"{left} {op} {right}"

    return emit(tree)


def show_code(op: str, params: dict) -> str:
    sel = params.get("selectors")
    if op == "list" and params.get("kind") == "functions":
        src = _sel_expr(sel) if sel else "db.functions"
        cond = _predicate(params.get("where")) if params.get("where") else None
        if src and (cond or not params.get("where")):
            lines = ["import fnmatch, re", "", "def run(db):", f"    for f in {src}:"]
            indent = "        "
            if cond:
                lines.append(f"{indent}if {cond}:")
                indent += "    "
            lines.append(f'{indent}yield {{"ea": f.start_ea, "name": db.functions.get_name(f), "size": f.size()}}')
            return "\n".join(lines) + "\n"
    if op == "decompile":
        src = _sel_expr(sel)
        if src:
            return "\n".join([
                "import fnmatch, re", "", "def run(db):", f"    for f in {src}:",
                "        text = db.pseudocode.get_text(f)",
                '        yield {"ea": f.start_ea, "name": db.functions.get_name(f), "pseudocode": "\\n".join(text)}',
            ]) + "\n"
    if op == "disasm":
        src = _sel_expr(sel)
        if src:
            return "\n".join([
                "import fnmatch, re", "", "def run(db):", f"    for f in {src}:",
                "        for line in db.functions.get_disassembly(f):",
                '            yield {"text": line}',
            ]) + "\n"
    if op == "rename" and sel and _sel_expr(sel) and "{" not in str(params.get("name", "")):
        return "\n".join([
            "def run(db):", f"    for f in {_sel_expr(sel)}:",
            f"        db.functions.set_name(f, {params.get('name')!r})",
        ]) + "\n"
    # generic: the exact engine call (runs under `icli exec`)
    request = json.dumps({"op": op, "params": params}, indent=None)
    return "\n".join([
        "# icli engine call; runs unchanged with: icli exec TARGET -c \"$(...)\" or as a file",
        "import json",
        "import icli.engine.rpc as rpc",
        "",
        "def run(db):",
        f"    result = rpc.call(db, json.dumps({json.loads(request)!r}))",
        "    if 'error' in result:",
        "        raise RuntimeError(result['error']['message'])",
        "    return result['records']",
    ]) + "\n"


def describe_selector(text: str) -> dict:
    return psel.parse(text)
