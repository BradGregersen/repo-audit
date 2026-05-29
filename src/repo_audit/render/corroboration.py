"""D-69 SAFE-06 trust-but-verify — deterministic render-time corroboration check.

The agent's SeverityCall.corroborated_by field is ADVISORY ONLY (CONTEXT
D-69). The deterministic check is_corroborated(finding, all_findings)
is authoritative — it inspects the structurally-counted Finding store
for source_tool diversity. Mismatch (agent claims corroboration where
deterministic check disagrees) is logged to meta.agent_corroboration_disputes
but never alters the rendered output.

The 2x2 grid for critical/blocker findings is:
  corroborated=True  + has_caveat=*       → 'critical-corroborated'
  corroborated=False + has_caveat=True    → 'critical-uncorroborated-with-caveat'
  corroborated=False + has_caveat=False   → 'critical-uncorroborated-fallthrough'
                                             (structurally impossible under SCH-03 for
                                              static evidence_type per Phase 1 D-17;
                                              defensive shape for runtime / future paths)

Plan 04-08 Task 2 wires these classes into the Jinja template's
findings table rendering.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from repo_audit.agent.schema import AgentScanReport
    from repo_audit.schema.finding import Finding

CriticalRenderClass = Literal[
    "critical-corroborated",
    "critical-uncorroborated-with-caveat",
    "critical-uncorroborated-fallthrough",
]


def is_corroborated(finding: "Finding", all_findings: "list[Finding]") -> bool:
    """D-69 — source_tool diversity >= 2 across same-dimension + same-file findings."""
    same_dim_same_file = [
        f
        for f in all_findings
        if f is not finding
        and getattr(f, "dimension", None) == getattr(finding, "dimension", None)
        and getattr(f, "file", None) == getattr(finding, "file", None)
    ]
    source_tools = {getattr(f, "source_tool", "") for f in same_dim_same_file} | {
        getattr(finding, "source_tool", "")
    }
    return len({t for t in source_tools if t}) >= 2


def classify_critical_finding(
    finding: "Finding",
    all_findings: "list[Finding]",
) -> CriticalRenderClass:
    """D-69 — return the 2x2-grid render class for a critical/blocker Finding."""
    if is_corroborated(finding, all_findings):
        return "critical-corroborated"
    if getattr(finding, "confidence_caveat", None):
        return "critical-uncorroborated-with-caveat"
    return "critical-uncorroborated-fallthrough"


def detect_corroboration_disputes(
    agent_output: "AgentScanReport | None",
    all_findings: "list[Finding]",
) -> list[dict[str, object]]:
    """Log agent_claim vs deterministic_check disagreements (D-69).

    Returns list[dict] entries with keys:
      - finding_ref: the agent's SeverityCall.finding_ref
      - agent_claim: the corroborated_by list the agent emitted
      - deterministic_result: True/False from is_corroborated
      - mismatch_kind: 'agent_claimed_corroboration_unsupported' |
                       'agent_silent_but_corroborated_in_findings'
    """
    if agent_output is None:
        return []
    disputes: list[dict[str, object]] = []
    # Build a lookup: finding_ref → Finding (best-effort match on
    # source_tool::rule_id::file:line).
    by_ref: dict[str, "Finding"] = {}
    for f in all_findings:
        ref = (
            f"{getattr(f, 'source_tool', '')}::"
            f"{getattr(f, 'rule_id', '') or ''}::"
            f"{getattr(f, 'file', '') or ''}:{getattr(f, 'line', '') or ''}"
        )
        by_ref[ref] = f
    for dim in agent_output.dimensions:
        for call in dim.severity_calls:
            target = by_ref.get(call.finding_ref)
            if target is None:
                continue  # unmatched ref — future plan logs as a separate dispute kind
            deterministic = is_corroborated(target, all_findings)
            agent_claims_corroboration = bool(call.corroborated_by)
            if agent_claims_corroboration and not deterministic:
                disputes.append(
                    {
                        "finding_ref": call.finding_ref,
                        "agent_claim": list(call.corroborated_by),
                        "deterministic_result": False,
                        "mismatch_kind": "agent_claimed_corroboration_unsupported",
                    }
                )
            elif (not agent_claims_corroboration) and deterministic:
                disputes.append(
                    {
                        "finding_ref": call.finding_ref,
                        "agent_claim": [],
                        "deterministic_result": True,
                        "mismatch_kind": "agent_silent_but_corroborated_in_findings",
                    }
                )
    return disputes


__all__ = [
    "CriticalRenderClass",
    "is_corroborated",
    "classify_critical_finding",
    "detect_corroboration_disputes",
]
