"""DG001-DG004 rules."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Export


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    group: str
    detail: str


def rule_tenancy_wide(export: Export) -> list:
    """DG001 HIGH: matching rule scopes to the whole tenancy (heuristic)."""
    out = []
    for g in export.dynamic_groups:
        if g.scopes_to_tenancy():
            out.append(
                Finding("DG001", "HIGH", g.name,
                        "matching rule appears tenancy-scoped (tenancy.id reference or no compartment/instance "
                        "qualifier); every matching resource in the tenancy joins this group - review the rule text")
            )
    return out


def rule_undocumented(export: Export) -> list:
    """DG002 MEDIUM: no description."""
    return [
        Finding("DG002", "MEDIUM", g.name,
                "no description recorded; the group's purpose exists only in someone's memory")
        for g in export.dynamic_groups if not g.description.strip()
    ]


def rule_unreferenced(export: Export) -> list:
    """DG003 MEDIUM: no policy statement in the export references the group."""
    haystack = "\n".join(export.policy_statements).lower()
    return [
        Finding("DG003", "MEDIUM", g.name,
                "no policy statement in this export references this group; defined but unused as far as "
                "the export records")
        for g in export.dynamic_groups if g.name.lower() not in haystack
    ]


def rule_empty_membership(export: Export) -> list:
    """DG004 LOW: zero matched resources recorded."""
    return [
        Finding("DG004", "LOW", g.name,
                "export records zero matched resources; membership is currently empty")
        for g in export.dynamic_groups if g.matched_count == 0
    ]


ALL_RULES = (
    rule_tenancy_wide,
    rule_undocumented,
    rule_unreferenced,
    rule_empty_membership,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(export: Export) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(export))
    findings.sort(key=lambda x: (_SEVERITY_RANK[x.severity], x.rule, x.group))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
