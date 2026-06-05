"""Socket.dev ``socket scan create --json`` -> Finding normalizer (BYO-02).

Socket.dev emits tool-native JSON (no SARIF), so this tiny normalizer maps its
``issues[]`` package/severity/issue-type shape into the shared :class:`Finding`
model. It copies the SARIF parser's ``_result_to_finding`` recipe so a
Socket-sourced Finding is structurally identical to a SARIF-sourced one:

    * ``evidence_type='static'`` — Socket is a static supply-chain analyser
      (SAFE-01: we never claim runtime).
    * ``confidence='candidate'`` — pre-verification; Phase 17 corroboration is
      the only promotion path (D-16-15).
    * the **candidate severity cap** holds: a Socket ``critical``/``high`` maps
      to a faithful ``critical`` that SCH-04 forbids at candidate, so it is
      DEMOTED to ``major`` before construction (the faithful severity is
      preserved in ``parsed_value['faithful_severity']`` as the Phase-17
      breadcrumb) — no ``candidate``+``critical`` Finding is ever built.
    * ``source_tool`` is tagged on every Finding (BYO-01 traceability).

DEFENSIVE per A6 (LOW-confidence fixture shape): a non-dict doc, a missing/
non-list ``issues``, or a non-dict entry is skipped; the function returns ``[]``
rather than raising. It NEVER raises across its boundary (D-25).
"""
from __future__ import annotations

from typing import Any

from repo_audit.adapters.sarif.parser import _CANDIDATE_CAP, _CAPPED_SEVERITIES
from repo_audit.schema.enums import Severity
from repo_audit.schema.finding import Evidence, Finding

# Socket.dev severity strings -> faithful Severity. Socket uses
# critical/high/medium/low; map to the project's 5-rung rubric.
_SOCKET_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "critical",
    "high": "critical",
    "medium": "major",
    "moderate": "major",
    "low": "minor",
    "info": "info",
    "informational": "info",
}

_CAPPED_CAVEAT = (
    "{source_tool} reported {faithful_severity}; capped at major at "
    "confidence=candidate per SCH-04 — pending Phase 17 corroboration."
)


def socket_json_to_findings(
    doc: Any,
    *,
    source_tool: str = "socket",
    default_dimension: str = "security",
) -> list[Finding]:
    """Map a Socket.dev scan JSON document into a list of Findings.

    Args:
        doc: a parsed ``socket scan create --json`` document. Expected shape:
            ``{"issues": [{"type", "severity", "package": {...},
            "title"/"description", "location": {"file"}}]}``.
        source_tool: the tool name stamped onto every Finding (BYO-01).
        default_dimension: the Dimension every Socket Finding lands in
            (supply-chain risk routes to ``security``).

    Returns:
        A flat list of Findings, one per well-formed ``issues[]`` entry.
        Malformed entries are skipped; a malformed document yields ``[]``.
        NEVER raises.
    """
    if not isinstance(doc, dict):
        return []
    issues = doc.get("issues")
    if not isinstance(issues, list):
        return []

    findings: list[Finding] = []
    for entry in issues:
        if not isinstance(entry, dict):
            continue
        finding = _entry_to_finding(
            entry, source_tool=source_tool, default_dimension=default_dimension
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _entry_to_finding(
    entry: dict[str, Any],
    *,
    source_tool: str,
    default_dimension: str,
) -> Finding | None:
    raw_sev = str(entry.get("severity") or "").strip().lower()
    faithful_severity: Severity = _SOCKET_SEVERITY_MAP.get(raw_sev, "info")

    issue_type = entry.get("type")
    pkg = entry.get("package") if isinstance(entry.get("package"), dict) else {}
    pkg_name = pkg.get("name")
    pkg_version = pkg.get("version")
    pkg_ecosystem = pkg.get("ecosystem")

    location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
    file = location.get("file")

    message = str(entry.get("title") or entry.get("description") or issue_type or "")

    rule_id = str(issue_type or "")

    # Candidate cap (mirrors the SARIF path): SCH-04 forbids candidate +
    # {critical, blocker}; demote to major and preserve the faithful severity.
    confidence_caveat: str | None = None
    if faithful_severity in _CAPPED_SEVERITIES:
        severity: Severity = _CANDIDATE_CAP
        confidence_caveat = _CAPPED_CAVEAT.format(
            source_tool=source_tool, faithful_severity=faithful_severity
        )
    else:
        severity = faithful_severity

    evidence = Evidence(
        tool=source_tool,
        output_snippet=message,
        parsed_value={
            "rule_id": rule_id,
            "issue_type": issue_type,
            "package": pkg_name,
            "package_version": pkg_version,
            "ecosystem": pkg_ecosystem,
            "faithful_severity": faithful_severity,
        },
    )

    return Finding(
        dimension=default_dimension,  # type: ignore[arg-type]
        severity=severity,
        file=file,
        line=None,
        evidence=evidence,
        evidence_type="static",
        confidence="candidate",
        source_tool=source_tool,
        rule_id=rule_id,
        confidence_caveat=confidence_caveat,
    )


__all__ = ["socket_json_to_findings"]
