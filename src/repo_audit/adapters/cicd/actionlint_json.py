"""actionlint ``{{json .}}`` -> Finding map (Phase 13, Plan 02, D-13-03).

A tiny, dedicated transform — NOT a fork of ``sarif_to_findings``. actionlint's
SARIF reporter is an impractical Go-template (Pitfall 1), so D-13-03 routes
actionlint through its native JSON (``-format '{{json .}}'``) into this map.

The map MIRRORS the Evidence/Finding construction shape of
``adapters/sarif/parser.py::_result_to_finding`` (it does NOT import or reuse it),
but reads actionlint's lowercase JSON keys — pinned by the Plan-01 fixture
``tests/adapters/cicd/fixtures/actionlint/sample.json`` (Assumption A1 RESOLVED:
keys are the Go-struct JSON tags ``message`` / ``filepath`` / ``line`` /
``column`` / ``kind`` / ``snippet``; ``EndColumn`` is NOT serialized).

Every Finding is:
  * ``dimension="process"``      — D-13-02 (a workflow-correctness linter).
  * ``severity="minor"``         — lint-level; trips neither the SCH-04 candidate
                                   cap (which bites only at critical/blocker) nor
                                   the SAFE-01 critical+static caveat requirement.
  * ``evidence_type="static"``   — SAFE-01: a static linter, never runtime.
  * ``confidence="candidate"``   — D-06-03; Phase 17 corroboration promotes.
  * ``source_tool="actionlint"``
  * ``rule_id=<entry "kind">``   — shellcheck / action / expression / syntax-check ...

A JSON entry missing ``line`` → ``Finding.line is None`` and
``Evidence.line_range is None`` (no crash). An empty array → ``[]``.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "actionlint"
# Lint-level severity: SCH-04's candidate cap (critical/blocker) and SAFE-01's
# critical+static caveat requirement are both no-ops at 'minor'.
_SEVERITY = "minor"


def _actionlint_json_to_findings(
    errors: list[dict[str, Any]],
    *,
    default_dimension: str = "process",
) -> list[Finding]:
    """Map actionlint ``{{json .}}`` entries to process-dimension Findings.

    Args:
        errors: the parsed actionlint JSON array (each entry a dict with the
            lowercase keys ``message`` / ``filepath`` / ``line`` / ``column`` /
            ``kind`` / ``snippet``). An empty list returns ``[]``.
        default_dimension: the routed dimension (``process`` by default; resolved
            from ``adapter.yaml`` by the caller).

    Returns:
        A list of candidate/static/minor Findings, one per entry. An entry
        without a ``line`` yields ``Finding.line is None`` + ``line_range is None``.
    """
    findings: list[Finding] = []
    for entry in errors:
        message = entry.get("message") or ""
        filepath = entry.get("filepath")
        line = entry.get("line")
        column = entry.get("column")
        kind = entry.get("kind") or ""
        snippet = entry.get("snippet")

        evidence = Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=message,
            parsed_value={
                "rule_id": kind,
                "column": column,
                "snippet": snippet,
            },
            line_range=(line, line) if line is not None else None,
        )
        findings.append(
            Finding(
                dimension=default_dimension,  # type: ignore[arg-type]
                severity=_SEVERITY,
                file=filepath,
                line=line,
                evidence=evidence,
                evidence_type="static",
                confidence="candidate",
                source_tool=_SOURCE_TOOL,
                rule_id=kind,
                confidence_caveat=None,
            )
        )
    return findings


__all__ = ["_actionlint_json_to_findings"]
