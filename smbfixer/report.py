"""Render findings as terminal text, Markdown, or JSON.

Every recommendation is labelled with the machine it is carried out on, and the report ends with
the steps grouped by machine, marking which ones `smbfixer apply` can make itself.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime

from smbfixer import configedit
from smbfixer.analysis.facts import Facts
from smbfixer.analysis.model import (
    CLIENT_NSMB,
    HOST_SMB_EXTRA,
    MACHINE_HEADINGS,
    Finding,
    Recommendation,
)

ICON = {"critical": "✖", "warning": "▲", "info": "●", "ok": "✔"}
COLOR = {"critical": "31", "warning": "33", "info": "36", "ok": "32"}

NSMB_FILE = "Mac: /etc/nsmb.conf"
EXTRA_FILE = "Unraid server: /boot/config/smb-extra.conf (Settings > SMB > SMB Extras)"

APPLY_NOTE = ("Steps marked [auto] can be made by `smbfixer apply`, which shows each change, asks before "
              "making it, keeps a backup and validates the result. Steps marked [you] must be done by hand; "
              "[check] steps only look and change nothing.")


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


def tag(r: Recommendation) -> str:
    return "check" if r.check else ("auto" if r.automatic else "you")


def proposed_files(facts: Facts, recs: list[Recommendation]) -> dict[str, tuple[str, str]]:
    """{label: (current text, proposed text)} for the config files the recommendations touch."""
    out = {}
    client = [r for r in recs if r.target == CLIENT_NSMB]
    if client:
        current = facts.snap.out("client", "nsmb_system")
        new = configedit.edit(current, client, sep="=")
        if new != current:
            out[NSMB_FILE] = (current, new)
    host = [r for r in recs if r.target == HOST_SMB_EXTRA]
    if host:
        current = facts.snap.out("host", "smb_extra")
        new = configedit.edit(current, host)
        if new != current:
            out[EXTRA_FILE] = (current, new)
    return out


def snippets(facts: Facts, findings: list[Finding]) -> dict[str, str]:
    return {label: new for label, (_, new) in proposed_files(facts, all_recs(findings)).items()}


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


def by_machine(recs: list[Recommendation]) -> dict[str, list[Recommendation]]:
    out: dict[str, list[Recommendation]] = {m: [] for m in MACHINE_HEADINGS}
    for r in recs:
        if r.target in {CLIENT_NSMB, HOST_SMB_EXTRA}:
            continue  # shown as one proposed file per machine
        out.setdefault(r.machine, []).append(r)
    return out


def _file_machine(label: str) -> str:
    return "Mac" if label == NSMB_FILE else "Unraid server"


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
            out.append(f"    → [{tag(r)}] {r.where}: {r.action}")
            if r.tradeoff and r.tradeoff != last_tradeoff:
                out.append(_c(f"      tradeoff: {r.tradeoff}", "2", color))
            last_tradeoff = r.tradeoff
        out.append("")

    recs = all_recs(findings)
    files = proposed_files(facts, recs)
    groups = by_machine(recs)
    if not files and not any(groups.values()):
        return "\n".join(out).rstrip() + "\n"
    out += [_c("What to do, by machine", "1", color), APPLY_NOTE, ""]
    for machine, heading in MACHINE_HEADINGS.items():
        machine_files = {k: v for k, v in files.items() if _file_machine(k) == machine}
        items = groups.get(machine, [])
        if not machine_files and not items:
            continue
        out.append(_c(heading, "1", color))
        for label, (_, new) in machine_files.items():
            out.append(f"  [auto] Replace {label.split(': ', 1)[1]} with:")
            out += [f"      {line}" for line in new.splitlines()]
            target = CLIENT_NSMB if label == NSMB_FILE else HOST_SMB_EXTRA
            for r in recs:
                if r.target == target and r.tradeoff:
                    out.append(_c(f"      ({r.action} is a tradeoff; apply asks about it separately)", "2", color))
        for r in items:
            out.append(f"  [{tag(r)}] {r.action}" + ("  (tradeoff)" if r.tradeoff else ""))
        out.append("")
    if files:
        out.append("After the files change: the Mac needs the share unmounted and remounted for nsmb.conf; "
                   "apply reloads Samba on the server itself.")
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
            out.append(f"- **[{tag(r)}] {r.where}**: `{r.action}` — {r.why}"
                       + (f" *Tradeoff: {r.tradeoff}*" if r.tradeoff else ""))
        if f.recommendations:
            out.append("")
    recs = all_recs(findings)
    files = proposed_files(facts, recs)
    groups = by_machine(recs)
    if files or any(groups.values()):
        out += ["## What to do, by machine", "", APPLY_NOTE, ""]
        for machine, heading in MACHINE_HEADINGS.items():
            machine_files = {k: v for k, v in files.items() if _file_machine(k) == machine}
            items = groups.get(machine, [])
            if not machine_files and not items:
                continue
            out += [f"### {heading}", ""]
            for label, (_, new) in machine_files.items():
                out += [f"- **[auto]** Replace `{label.split(': ', 1)[1]}` with:", "", "  ```ini",
                        *[f"  {line}" for line in new.splitlines()], "  ```"]
            out += [f"- **[{tag(r)}]** {r.action}" + (" *(tradeoff)*" if r.tradeoff else "") for r in items]
            out.append("")
    return "\n".join(out)


def as_json(facts: Facts, findings: list[Finding]) -> str:
    def rec(r: Recommendation) -> dict:
        return {"machine": r.machine, "where": r.where, "action": r.action, "why": r.why,
                "tradeoff": r.tradeoff, "mode": tag(r)}

    return json.dumps({
        "created_at": facts.snap.created_at,
        "context": context_lines(facts),
        "findings": [{**f.to_dict(), "recommendations": [rec(r) for r in f.recommendations]} for f in findings],
        "files": snippets(facts, findings),
    }, indent=2, default=str)
