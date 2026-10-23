"""Turn a snapshot into findings and configuration recommendations."""

from __future__ import annotations

from smbfixer.analysis.facts import Facts, build_facts
from smbfixer.analysis.model import SEVERITY_ORDER, Finding, Recommendation
from smbfixer.analysis.rules import RULES
from smbfixer.snapshot import Snapshot


def analyze(snap: Snapshot) -> tuple[Facts, list[Finding]]:
    facts = build_facts(snap)
    findings: list[Finding] = []
    for rule in RULES:
        try:
            findings.extend(rule(facts))
        except Exception as exc:  # a broken rule must not hide the others
            findings.append(
                Finding(
                    id=f"internal.{rule.__name__}",
                    severity="info",
                    category="internal",
                    title=f"Rule {rule.__name__} could not run",
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.category, f.id))
    return facts, findings


__all__ = ["analyze", "Facts", "Finding", "Recommendation"]
