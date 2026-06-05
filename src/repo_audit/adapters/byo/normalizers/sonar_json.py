"""SonarQube ``api/issues/search`` (or sonarqube-cli) -> Finding normalizer.

SonarQube emits tool-native JSON (no SARIF), so this tiny normalizer maps its
``issues[]`` shape into the shared :class:`Finding` model. It copies the SARIF
parser's ``_result_to_finding`` recipe so a Sonar-sourced Finding is
structurally identical to a SARIF-sourced one:

    * ``evidence_type='static'`` (SAFE-01: Sonar is a static analyser).
    * ``confidence='candidate'`` (Phase 17 corroboration is the only promotion
      path, D-16-15).
    * the **candidate severity cap** holds: Sonar's ``BLOCKER``/``CRITICAL`` map
      to a faithful ``blocker``/``critical`` that SCH-04 forbids at candidate, so
      they are DEMOTED to ``major`` before construction (faithful severity
      preserved in ``parsed_value['faithful_severity']``) — no
      ``candidate``+``critical`` Finding is ever built.
    * ``source_tool`` is tagged on every Finding (BYO-01 traceability).

DEFENSIVE per A5 (LOW-confidence fixture shape): a non-dict doc, a missing/
non-list ``issues``, or a non-dict entry is skipped; the function returns ``[]``
rather than raising. It NEVER raises across its boundary (D-25).
"""
from __future__ import annotations

from typing import Any

from repo_audit.adapters.sarif.parser import _CANDIDATE_CAP, _CAPPED_SEVERITIES
from repo_audit.schema.enums import Severity
from repo_audit.schema.finding import Evidence, Finding

# SonarQube severity strings -> faithful Severity. Sonar uses
# BLOCKER/CRITICAL/MAJOR/MINOR/INFO.
_SONAR_SEVERITY_MAP: dict[str, Severity] = {
    "BLOCKER": "blocker",
    "CRITICAL": "critical",
    "MAJOR": "major",
    "MINOR": "minor",
    "INFO": "info",
}

_CAPPED_CAVEAT = (
    "{source_tool} reported {faithful_severity}; capped at major at "
    "confidence=candidate per SCH-04 — pending Phase 17 corroboration."
)


def sonar_json_to_findings(
    doc: Any,
    *,
    source_tool: str = "sonarqube",
    default_dimension: str = "quality",
) -> list[Finding]:
    """Map a SonarQube issues/search JSON document into a list of Findings.

    Args:
        doc: a parsed ``api/issues/search`` document. Expected shape:
            ``{"issues": [{"rule", "severity", "component", "line",
            "message"}]}``.
        source_tool: the tool name stamped onto every Finding (BYO-01).
        default_dimension: the Dimension every Sonar Finding lands in
            (code smells / maintainability route to ``quality``).

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
    raw_sev = str(entry.get("severity") or "").strip().upper()
    faithful_severity: Severity = _SONAR_SEVERITY_MAP.get(raw_sev, "info")

    rule_id = str(entry.get("rule") or "")
    # Sonar ``component`` is "<projectKey>:<path>"; strip the project key prefix
    # to recover the repo-relative file path. Defensive: keep the raw value if it
    # has no ':' separator.
    component = entry.get("component")
    file = _component_to_file(component)

    raw_line = entry.get("line")
    line = raw_line if isinstance(raw_line, int) else None

    message = str(entry.get("message") or rule_id or "")

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
            "sonar_severity": raw_sev or None,
            "issue_type": entry.get("type"),
            "faithful_severity": faithful_severity,
        },
        line_range=(line, line) if line is not None else None,
    )

    return Finding(
        dimension=default_dimension,  # type: ignore[arg-type]
        severity=severity,
        file=file,
        line=line,
        evidence=evidence,
        evidence_type="static",
        confidence="candidate",
        source_tool=source_tool,
        rule_id=rule_id,
        confidence_caveat=confidence_caveat,
    )


def _component_to_file(component: Any) -> str | None:
    """Recover the repo-relative file path from a Sonar ``component`` key.

    Sonar formats ``component`` as ``"<projectKey>:<path>"``. Returns the path
    portion, or the raw value if there is no separator, or ``None`` if absent.
    """
    if not isinstance(component, str) or not component:
        return None
    _, sep, path = component.partition(":")
    return path if sep else component


__all__ = ["sonar_json_to_findings"]
