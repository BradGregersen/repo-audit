"""Generic SARIF 2.1.0 -> Finding parser (FND-01).

``sarif_to_findings`` is the ONE parse path every later security tool
(Phases 7–16) plugs into. Adding a new SARIF-emitting tool is a per-tool
``severity_map`` + ``default_dimension`` (D-06-04/D-06-05), never a code edit
here — every tool's SARIF round-trips through this single audited function.

Key invariants
---------------
- ``evidence_type = "static"`` — SARIF tools are static analysers; we never
  claim runtime (SAFE-01).
- ``confidence = "candidate"`` — pre-verification (D-06-03). Phase 17
  corroboration is what promotes findings up the confidence ladder.
- ``source_tool`` is threaded onto every Finding (BYO-01 traceability).
- **Candidate severity cap (D-06-02/D-06-03, REVISED 2026-06-01):** every
  emitted Finding sits at ``confidence="candidate"``. SCH-04 forbids
  ``candidate`` + severity in ``{critical, blocker}`` *regardless of a
  confidence_caveat* — a caveat satisfies SAFE-01 but NOT SCH-04, so a
  faithful ``critical`` at ``candidate`` is structurally impossible. The
  faithful severity from :func:`map_severity` is therefore **capped to
  ``major`` as a pre-construction step**. The tool's raw signal is NOT lost:
  the pre-cap faithful severity and the SARIF level + security-severity are
  preserved in ``evidence.parsed_value``, and a ``confidence_caveat`` records
  the demotion as the Phase-17 promotion breadcrumb. Phase 17 corroboration is
  the only path that promotes a Finding back up to ``critical``/``blocker``.
  The cap is computed BEFORE the single ``Finding(...)`` construction — the
  parser never builds an invalid Finding and then retries on a validation
  failure (verified by grep: no validation-error handler guards construction).
"""
from __future__ import annotations

from typing import Any, get_args

from repo_audit.adapters.sarif.severity import map_severity
from repo_audit.schema.enums import Dimension, Severity
from repo_audit.schema.finding import Evidence, Finding

# SCH-04 forbids confidence=candidate + severity in {critical, blocker}. Every
# Finding emitted here is candidate, so a faithful critical/blocker is DEMOTED to
# major before construction (D-06-02 REVISED). This caveat is the Phase-17
# promotion breadcrumb: it records the faithful severity that was capped.
_CAPPED_CRITICAL_CAVEAT = (
    "{source_tool} reported {faithful_severity} (security-severity {sev}); "
    "capped at major at confidence=candidate per SCH-04 — pending Phase 17 "
    "corroboration."
)

# Faithful severities that SCH-04 forbids at confidence=candidate and that the
# parser therefore demotes to 'major'.
_CAPPED_SEVERITIES: frozenset[Severity] = frozenset({"critical", "blocker"})

# The severity every capped Finding lands at (highest severity allowed at the
# candidate rung).
_CANDIDATE_CAP: Severity = "major"

_VALID_DIMENSIONS: frozenset[str] = frozenset(get_args(Dimension))


def _extract_location(result: dict[str, Any]) -> tuple[str | None, int | None]:
    """Pull (uri, startLine) from result.locations[0].physicalLocation."""
    locations = result.get("locations") or []
    if not locations:
        return None, None
    physical = (locations[0] or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri")
    region = physical.get("region") or {}
    start_line = region.get("startLine")
    return uri, start_line


def _lookup_security_severity(
    result: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
) -> str | None:
    """Find the security-severity for a result.

    Lookup order (prefer the rule-level property, per the plan):
      1. runs[].tool.driver.rules[] matched by ruleId -> properties.security-severity
      2. result.properties.security-severity (fallback)
    """
    rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
    if rule_id and rule_id in rules_by_id:
        props = rules_by_id[rule_id].get("properties") or {}
        if "security-severity" in props:
            return props["security-severity"]
    props = result.get("properties") or {}
    return props.get("security-severity")


def sarif_to_findings(
    sarif_dict: dict[str, Any],
    *,
    source_tool: str,
    default_dimension: str,
    severity_map: dict[str, Severity],
) -> list[Finding]:
    """Parse a SARIF 2.1.0 document into a list of Findings.

    Args:
        sarif_dict: a parsed SARIF 2.1.0 document.
        source_tool: the tool name stamped onto every Finding (BYO-01).
        default_dimension: the Dimension used for every Finding (SARIF gives no
            dimension signal; D-06-05 caller-supplied fallback). Validated.
        severity_map: per-tool ``{level: Severity}`` overrides, resolved at
            call time (D-06-04).

    Returns:
        A flat list of Findings, one per ``runs[].results[]`` entry.

    Raises:
        ValueError: if ``default_dimension`` is not a member of Dimension
            (fail loud at call entry — a mis-configured adapter must not
            silently emit garbage dimensions).
    """
    if default_dimension not in _VALID_DIMENSIONS:
        raise ValueError(
            f"default_dimension={default_dimension!r} is not a valid Dimension; "
            f"expected one of {sorted(_VALID_DIMENSIONS)}."
        )

    findings: list[Finding] = []
    for run in sarif_dict.get("runs") or []:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        rules_by_id: dict[str, dict[str, Any]] = {
            rule["id"]: rule
            for rule in (driver.get("rules") or [])
            if isinstance(rule, dict) and "id" in rule
        }
        for result in run.get("results") or []:
            findings.append(
                _result_to_finding(
                    result,
                    rules_by_id=rules_by_id,
                    source_tool=source_tool,
                    default_dimension=default_dimension,
                    severity_map=severity_map,
                )
            )
    return findings


def _result_to_finding(
    result: dict[str, Any],
    *,
    rules_by_id: dict[str, dict[str, Any]],
    source_tool: str,
    default_dimension: str,
    severity_map: dict[str, Severity],
) -> Finding:
    rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or ""
    message = ((result.get("message") or {}).get("text")) or ""
    level = result.get("level")
    file, line = _extract_location(result)
    security_severity = _lookup_security_severity(result, rules_by_id)

    faithful_severity = map_severity(level, security_severity, severity_map)

    # D-06-02/D-06-03 (REVISED): apply the candidate cap as a pre-construction
    # step. Every Finding is confidence=candidate, and SCH-04 forbids candidate
    # + {critical, blocker} regardless of any caveat. Demote to 'major' and
    # record the faithful severity as the Phase-17 promotion breadcrumb. The cap
    # is computed BEFORE the single Finding(...) call — never catch-and-retry.
    confidence_caveat: str | None = None
    if faithful_severity in _CAPPED_SEVERITIES:
        severity: Severity = _CANDIDATE_CAP
        confidence_caveat = _CAPPED_CRITICAL_CAVEAT.format(
            source_tool=source_tool,
            faithful_severity=faithful_severity,
            sev=security_severity if security_severity is not None else "n/a",
        )
    else:
        severity = faithful_severity

    evidence = Evidence(
        tool=source_tool,
        output_snippet=message,
        parsed_value={
            "rule_id": rule_id,
            "sarif_level": level,
            "security_severity": security_severity,
            # Preserve the pre-cap faithful severity so Phase 17 can promote.
            "faithful_severity": faithful_severity,
        },
        line_range=(line, line) if line is not None else None,
    )

    return Finding(
        dimension=default_dimension,  # type: ignore[arg-type]  # validated above
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
