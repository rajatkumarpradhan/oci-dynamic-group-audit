"""Data model + export loading for the dynamic-group audit."""

from __future__ import annotations

import json
from dataclasses import dataclass


class ExportError(ValueError):
    """Raised when an export file is malformed."""


@dataclass(frozen=True)
class DynamicGroup:
    ocid: str
    name: str
    description: str
    matching_rule: str
    matched_count: int

    def scopes_to_tenancy(self) -> bool:
        rule = self.matching_rule.lower()
        if "tenancy.id" in rule:
            return True
        # no compartment or instance qualifier at all -> effectively tenancy-wide
        return "compartment" not in rule and "instance." not in rule


@dataclass(frozen=True)
class Export:
    dynamic_groups: tuple
    policy_statements: tuple


def load_export(path: str) -> Export:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ExportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("dynamic_groups"), list):
        raise ExportError(f"{path}: top level must be an object with a 'dynamic_groups' list")
    groups = []
    for i, g in enumerate(raw["dynamic_groups"]):
        where = f"dynamic_groups[{i}]"
        for req in ("ocid", "name", "matching_rule"):
            if req not in g:
                raise ExportError(f"{where}: missing required field {req!r}")
        mc = g.get("matched_count", 0)
        if not isinstance(mc, int) or isinstance(mc, bool) or mc < 0:
            raise ExportError(f"{where}: matched_count must be a non-negative integer")
        groups.append(
            DynamicGroup(
                ocid=g["ocid"],
                name=g["name"],
                description=g.get("description", "") or "",
                matching_rule=g["matching_rule"],
                matched_count=mc,
            )
        )
    statements = []
    for p in raw.get("policies", []):
        statements.extend(p.get("statements", []))
    return Export(dynamic_groups=tuple(groups), policy_statements=tuple(statements))
