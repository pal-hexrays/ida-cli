"""Render a node/edge graph as DOT, GDL or JSON (pure Python)."""

from __future__ import annotations

import json
from typing import Any


def _q(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\l") + '"'


def render(nodes: list[dict], edges: list[dict], fmt: str, name: str = "g") -> str:
    """``nodes``: {id, label, ...}; ``edges``: {src, dst, label?, ...}."""
    if fmt == "json":
        return json.dumps({"name": name, "nodes": nodes, "edges": edges}, indent=2) + "\n"
    if fmt == "dot":
        lines = [f"digraph {_q(name)} {{", '  node [shape=box, fontname="monospace"];']
        for n in nodes:
            attrs = [f"label={_q(n.get('label', n['id']))}"]
            if n.get("color"):
                attrs.append(f'style=filled, fillcolor="#{n["color"]}"')
            lines.append(f"  {_q(n['id'])} [{', '.join(attrs)}];")
        for e in edges:
            label = f" [label={_q(e['label'])}]" if e.get("label") else ""
            lines.append(f"  {_q(e['src'])} -> {_q(e['dst'])}{label};")
        lines.append("}")
        return "\n".join(lines) + "\n"
    if fmt == "gdl":
        lines = ["graph: {", f"  title: {_q(name)}", "  manhattan_edges: yes", "  layoutalgorithm: mindepth"]
        for n in nodes:
            lines.append(f"  node: {{ title: {_q(n['id'])} label: {_q(n.get('label', n['id']))} }}")
        for e in edges:
            label = f" label: {_q(e['label'])}" if e.get("label") else ""
            lines.append(f"  edge: {{ sourcename: {_q(e['src'])} targetname: {_q(e['dst'])}{label} }}")
        lines.append("}")
        return "\n".join(lines) + "\n"
    raise ValueError(f"unknown graph format {fmt!r}")


def to_svg(dot_text: str) -> str:
    """Render DOT to SVG with graphviz when available, else a minimal layout."""
    import shutil
    import subprocess

    if shutil.which("dot"):
        res = subprocess.run(["dot", "-Tsvg"], input=dot_text, capture_output=True, text=True, timeout=120)
        if res.returncode == 0:
            return res.stdout
    return _fallback_svg(dot_text)


def _fallback_svg(dot_text: str) -> str:
    import re

    nodes = re.findall(r'^\s*"((?:[^"\\]|\\.)*)" \[label="((?:[^"\\]|\\.)*)"', dot_text, re.M)
    edges = re.findall(r'^\s*"((?:[^"\\]|\\.)*)" -> "((?:[^"\\]|\\.)*)"', dot_text, re.M)
    pos: dict[str, tuple[int, int]] = {}
    row_h, col_w = 40, 260
    for i, (nid, _) in enumerate(nodes):
        pos[nid] = (20 + (i % 4) * col_w, 20 + (i // 4) * row_h * 2)
    height = 40 + ((len(nodes) + 3) // 4) * row_h * 2
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{4 * col_w + 40}" height="{height}" '
           'font-family="monospace" font-size="11">']
    for a, b in edges:
        if a in pos and b in pos:
            (x1, y1), (x2, y2) = pos[a], pos[b]
            out.append(f'<line x1="{x1 + 100}" y1="{y1 + 24}" x2="{x2 + 100}" y2="{y2}" stroke="#888"/>')
    for nid, label in nodes:
        x, y = pos[nid]
        text = label.replace("\\l", " ").replace("&", "&amp;").replace("<", "&lt;")[:36]
        out.append(f'<rect x="{x}" y="{y}" width="200" height="24" fill="#f4f4f4" stroke="#333"/>')
        out.append(f'<text x="{x + 6}" y="{y + 16}">{text}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"
