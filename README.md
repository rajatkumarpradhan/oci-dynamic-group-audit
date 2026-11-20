# oci-dynamic-group-audit

**Category: custom portfolio tool.** Pure Python command-line auditor. It does **not** wire any
built-in OCI services together - it is the *custom* project in its daily pair (the built-in
services project is `oci-ootb-ocir-image-hygiene`).

## The problem

Dynamic groups decide which compute instances (and other resources) get IAM permissions, and
their matching rules are deceptively easy to write too broadly: one rule that matches every
instance in the tenancy, and every future workload inherits whatever policies reference the
group. The other quiet failure mode is the opposite - a group defined, documented by nobody,
referenced by nothing, matching nothing. This tool audits an **offline export** of dynamic
groups and the policies that reference them, and flags what the export records.

## What it does

Reads a JSON export (schema below, synthetic samples included) and applies four rules:

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| DG001 | HIGH | A matching rule scopes to the whole tenancy (contains `tenancy.id` or has no compartment/instance qualifier recorded) - every current and future matching resource in the tenancy joins this group. |
| DG002 | MEDIUM | A dynamic group has no description - its purpose exists only in someone's memory. |
| DG003 | MEDIUM | No policy statement in the export references the group - defined but unused (as far as this export records). |
| DG004 | LOW | The export records zero matched resources for the group - currently empty membership. |

Exit code: `2` if any HIGH finding, `1` if only MEDIUM/LOW, `0` when clean.

## Run it

```bash
python -m dg_audit.cli samples/groups_messy.json   # exits 2, all 4 rules fire
python -m dg_audit.cli samples/groups_clean.json   # exits 0
python -m unittest discover -s tests -v            # 19 tests, stdlib only
```

## Export schema

```json
{
  "dynamic_groups": [
    {"ocid": "ocid1.dynamicgroup.oc1..g1", "name": "prod-workers",
     "description": "Prod worker instances in compartment X",
     "matching_rule": "all {instance.compartment.id = 'ocid1.compartment.oc1..c1'}",
     "matched_count": 12}
  ],
  "policies": [
    {"name": "prod-workers-policy",
     "statements": ["Allow dynamic-group prod-workers to read objects in compartment prod"]}
  ]
}
```

## Honest limits

- **Offline only**: the export is synthetic; nothing calls the OCI IAM API and no matching
  rule is evaluated against real resources.
- DG001 is a text-heuristic on the rule string: it looks for tenancy-level scoping
  (`tenancy.id`) or a missing compartment/instance qualifier. Matching-rule syntax is richer
  than this heuristic; a HIGH here is a prompt to review the rule, not proof it is too broad.
- DG003/DG004 describe what the export records. A group may be referenced by policies outside
  the export, and `matched_count` is a point-in-time snapshot.
- Findings do not evaluate whether any policy statement is itself appropriate.

## Project status

Built as a daily portfolio project. 19 unit tests, green locally and in CI
(`.github/workflows/ci.yml`, Python 3.10/3.11/3.12). No paid services, no live cloud calls.
