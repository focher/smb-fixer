"""Render findings as terminal text, Markdown, or JSON, plus merged config snippets."""

from __future__ import annotations

import json
import sys
from datetime import datetime

from smbfixer.analysis.facts import Facts
from smbfixer.analysis.model import CLIENT_NSMB, HOST_SMB_EXTRA, Finding, Recommendation

ICON = {"critical": "✖", "warning": "▲", "info": "●", "ok": "✔"}
COLOR = {"critical": "31", "warning": "33", "info": "36", "ok": "32"}


def _c(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def all_recs(findings: list[Finding]) -> list[Recommendation]:
    seen, out = set(), []
    for f in findings:
        for r in f.recommendations:
            key = (r.target, r.section, r.action)
            if key not in seen:
                seen.add(key)
                out.append(r)
    return out


def ini_snippet(recs: list[Recommendation], existing: dict[str, dict[str, str]] | None = None,
                sep: str = " = ") -> str:
    """Merge recommended key/value pairs into INI sections (later recs for the same key win)."""
    sections: dict[str, dict[str, str]] = {}
    for name, values in (existing or {}).items():
        sections[name] = dict(values)
    for r in recs:
        key, _, value = r.action.partition("=")
        sections.setdefault(r.section or "global", {})[key.strip()] = value.strip()
    lines = []
    for name, values in sections.items():
        lines.append(f"[{name}]")
        lines += [f"{k}{sep}{v}" for k, v in values.items()]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def snippets(facts: Facts, findings: list[Finding]) -> dict[str, str]:
    recs = all_recs(findings)
    out = {}
    client = [r for r in recs if r.target == CLIENT_NSMB]
    if client:
        existing = {"default": dict(facts.nsmb)} if facts.nsmb else None
        out["/etc/nsmb.conf (client)"] = ini_snippet(client, existing, sep="=")
    host = [r for r in recs if r.target == HOST_SMB_EXTRA]
    if host:
        out["/boot/config/smb-extra.conf (host)"] = ini_snippet(host, facts.smb_extra or None)
    return out


def summary_line(findings: list[Finding]) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "warning", "info")}
    return f"{counts['critical']} critical, {counts['warning']} warning, {counts['info']} info"


def context_lines(facts: Facts) -> list[str]:
    s = facts.snap.meta
    lines = [f"Host: {s.get('host_address') or '?'} ({s.get('host_ip') or 'unresolved'})"]
    if facts.unraid_version:
        lines.append(f"Unraid {facts.unraid_version}, Samba {'.'.join(map(str, facts.samba_version)) or '?'}")
    if facts.macos_version:
        lines.append(f"macOS {facts.macos_version}")
    if facts.mount:
        lines.append(f"Share: {facts.mount.share} mounted at {facts.mount.mount_point}"
                     + (f" ({facts.attr('SMB_VERSION')})" if facts.attr("SMB_VERSION") else ""))
    if facts.client_iface:
        lines.append(f"Client path: {facts.client_iface} {facts.client_iface_port} "
                     f"mtu {facts.client_iface_info.get('mtu', '?')}")
    if facts.host_route.get("dev"):
        lines.append(f"Host path: {facts.host_route['dev']} -> {', '.join(facts.host_phys) or '?'}")
    return lines


def text(facts: Facts, findings: list[Finding], color: bool | None = None, verbose: bool = False) -> str:
    color = sys.stdout.isatty() if color is None else color
    out = [_c("SMB Fixer report", "1", color), *context_lines(facts), summary_line(findings), ""]
    for f in findings:
        out.append(_c(f"{ICON[f.severity]} [{f.severity.upper()}] {f.title}", COLOR[f.severity], color))
        if f.detail:
            out.append(f"    {f.detail}")
        for e in f.evidence[: None if verbose else 4]:
            out.append(_c(f"      · {e}", "2", color))
        last_tradeoff = ""
        for r in f.recommendations:
            out.append(f"    → {r.target}: {r.action}")
            if r.tradeoff and r.tradeoff != last_tradeoff:
                out.append(_c(f"      tradeoff: {r.tradeoff}", "2", color))
            last_tradeoff = r.tradeoff
        out.append("")
    snip = snippets(facts, findings)
    if snip:
        out.append(_c("Proposed configuration (merged with what is already there)", "1", color))
        for title, body in snip.items():
            out.append(f"--- {title}")
            out.append(body)
    others = [r for r in all_recs(findings) if r.target not in {CLIENT_NSMB, HOST_SMB_EXTRA}]
    if others:
        out.append(_c("Other steps", "1", color))
        out += [f"  - {r.target}: {r.action}" for r in others]
    if snip:
        out += ["", "After editing smb-extra.conf run `smbcontrol smbd reload-config` on the host (or restart the",
                "array). After editing /etc/nsmb.conf unmount and remount the share on the Mac."]
    return "\n".join(out).rstrip() + "\n"


def markdown(facts: Facts, findings: list[Finding]) -> str:
    when = datetime.fromtimestamp(facts.snap.created_at).strftime("%Y-%m-%d %H:%M")
    out = [f"# SMB Fixer report — {when}", "", *[f"- {line}" for line in context_lines(facts)],
           f"- **{summary_line(findings)}**", ""]
    for f in findings:
        out += [f"## {ICON[f.severity]} {f.title}", f"*{f.severity} · {f.category} · `{f.id}`*", ""]
        if f.detail:
            out += [f.detail, ""]
        if f.evidence:
            out += ["```", *f.evidence, "```", ""]
        for r in f.recommendations:
            out.append(f"- **{r.target}**: `{r.action}` — {r.why}" + (f" *Tradeoff: {r.tradeoff}*" if r.tradeoff else ""))
        if f.recommendations:
            out.append("")
    snip = snippets(facts, findings)
    if snip:
        out += ["## Proposed configuration", ""]
        for title, body in snip.items():
            out += [f"### {title}", "```ini", body.rstrip(), "```", ""]
    return "\n".join(out)


def as_json(facts: Facts, findings: list[Finding]) -> str:
    return json.dumps({
        "created_at": facts.snap.created_at,
        "context": context_lines(facts),
        "findings": [f.to_dict() for f in findings],
        "snippets": snippets(facts, findings),
    }, indent=2, default=str)
