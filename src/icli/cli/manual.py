"""The icli(1) manual shipped with the package; renders help topics."""

from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from importlib import resources

TOPICS = {
    "selectors": ("SELECTORS", None),
    "fields": ("FIELDS AND TEMPLATES", "Common fields"),
    "templates": ("FIELDS AND TEMPLATES", "Templates"),
    "formats": ("OUTPUT FORMATS", None),
    "exit-codes": ("EXIT STATUS", None),
    "journal": ("CONCEPTS", "The journal"),
    "cache": ("CONCEPTS", "Database cache"),
    "targets": ("CONCEPTS", "Targets"),
    "lifecycle": ("CONCEPTS", "Analysis lifecycle"),
    "recipes": ("COMMANDS", "Automation"),
    "settings": ("CONFIGURATION", None),
    "environment": ("ENVIRONMENT", None),
    "exec": ("COMMANDS", "Automation"),
    "examples": ("EXAMPLES", None),
    "global-options": ("GLOBAL OPTIONS", None),
    "load-options": ("LOAD OPTIONS", None),
}


def source() -> str:
    return resources.files("icli.data").joinpath("icli.1").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def rendered(width: int = 100) -> str:
    text = source()
    for tool in (["mandoc", "-T", "utf8", "-O", f"width={width}"], ["groff", "-man", "-Tutf8", "-P", "-c"]):
        if shutil.which(tool[0]):
            try:
                out = subprocess.run(tool, input=text, capture_output=True, text=True, timeout=20).stdout
                if out.strip():
                    return re.sub(r".\x08", "", out)
            except (OSError, subprocess.SubprocessError):
                pass
    return _strip_roff(text)


def _strip_roff(text: str) -> str:
    """Crude roff-to-text for systems without mandoc/groff."""
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith(('.\\"', "'\\\"")):
            continue
        m = re.match(r"^\.(SH|SS)\s+\"?(.*?)\"?$", line)
        if m:
            out.append("" if not out else "")
            out.append(m.group(2) if m.group(1) == "SH" else "   " + m.group(2))
            continue
        if line.startswith("."):
            body = re.sub(r"^\.\S+\s*", "", line)
            if not body:
                if line.startswith((".PP", ".TP", ".IP")):
                    out.append("")
                continue
            line = body.replace('"', "")
        line = re.sub(r"\\f[BIRP]|\\f\(CB|\\f\(CR", "", line)
        line = line.replace("\\-", "-").replace("\\(aq", "'").replace("\\e", "\\").replace("\\(bu", "*")
        line = re.sub(r"\\[&|^]", "", line)
        out.append("       " + line)
    return "\n".join(out)


def section(name: str, sub: str | None = None) -> str:
    """Text of one top-level section (and optionally one subsection)."""
    lines = rendered().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.rstrip() == name:
            start = i
            break
    if start is None:
        return ""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j] and not lines[j][0].isspace() and lines[j].isupper():
            end = j
            break
    body = lines[start:end]
    if sub is None:
        return "\n".join(body).rstrip() + "\n"
    s = None
    for i, line in enumerate(body):
        if line.strip() == sub and line.startswith("   ") and not line.startswith("       "):
            s = i
            break
    if s is None:
        return "\n".join(body).rstrip() + "\n"
    e = len(body)
    for j in range(s + 1, len(body)):
        if body[j].startswith("   ") and not body[j].startswith("    ") and body[j].strip():
            e = j
            break
    return "\n".join([name, *body[s:e]]).rstrip() + "\n"


def command_entry(command: str) -> str:
    """The manual's entry for one command (under COMMANDS)."""
    lines = rendered().splitlines()
    out: list[str] = []
    capturing = False
    pattern = re.compile(rf"^\s{{7}}icli {re.escape(command)}\b")
    for line in lines:
        if pattern.match(line):
            capturing = True
            out.append(line)
            continue
        if capturing:
            if re.match(r"^\s{7}icli \S", line) and not pattern.match(line):
                break
            if line and not line.startswith(" "):
                break
            if re.match(r"^\s{3}\S", line):
                break
            out.append(line)
    return "\n".join(out).rstrip() + ("\n" if out else "")
