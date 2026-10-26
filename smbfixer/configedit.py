"""Edit INI-style config files (nsmb.conf, smb-extra.conf) line by line.

Only the lines a recommendation touches change; comments, ordering and unrelated settings are kept,
so the proposed file in the report is exactly what `smbfixer apply` writes.
"""

from __future__ import annotations

import re

from smbfixer.analysis.model import Recommendation

_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _norm(key: str) -> str:
    # Samba ignores case and whitespace in parameter names ("strict sync" == "strictsync").
    return re.sub(r"\s+", "", key.lower())


def _key_of(line: str) -> str | None:
    s = line.strip()
    if not s or s[0] in "#;" or "=" not in s or _SECTION.match(s):
        return None
    return _norm(s.partition("=")[0])


def _sections(lines: list[str]) -> list[tuple[str, int, int]]:
    """(name, start, end) for each section; the preamble before any header is named ''."""
    out, name, start = [], "", 0
    for i, line in enumerate(lines):
        m = _SECTION.match(line)
        if m:
            out.append((name, start, i))
            name, start = m.group(1).strip(), i
    out.append((name, start, len(lines)))
    return out


def _find(lines: list[str], section: str) -> tuple[int, int] | None:
    for name, start, end in _sections(lines):
        if name.lower() == section.lower():
            return start, end
    return None


def edit(text: str, recs: list[Recommendation], sep: str = " = ") -> str:
    lines = text.splitlines()
    for r in recs:
        if r.drop_lines:
            bad = {b.strip() for b in r.drop_lines}
            lines = [line for line in lines if line.strip() not in bad]
            continue
        section = r.section or "global"
        span = _find(lines, section)
        if r.remove_key:
            if span:
                start, end = span
                target = _norm(r.remove_key)
                lines = lines[:start] + [line for line in lines[start:end] if _key_of(line) != target] + lines[end:]
            continue
        key, _, value = r.action.partition("=")
        key, value = key.strip(), value.strip()
        new_line = f"{key}{sep}{value}"
        if not span:
            if lines and lines[-1].strip():
                lines.append("")
            lines += [f"[{section}]", new_line]
            continue
        start, end = span
        for i in range(start, end):
            if _key_of(lines[i]) == _norm(key):
                indent = re.match(r"^\s*", lines[i]).group(0)
                lines[i] = indent + new_line
                break
        else:
            insert = end
            while insert > start + 1 and not lines[insert - 1].strip():
                insert -= 1
            lines.insert(insert, new_line)
    # drop sections left empty by removals
    out: list[str] = []
    for name, start, end in _sections(lines):
        body = lines[start:end]
        has_content = any(line.strip() and not _SECTION.match(line) for line in body)
        if name and not has_content:
            continue
        out += body
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n" if out else ""
