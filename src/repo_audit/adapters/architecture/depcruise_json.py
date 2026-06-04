"""dependency-cruiser ``--output-type json`` → Finding map (Phase 14, Plan 02, ARCH-01).

A tiny, dedicated transform — NOT a fork of ``sarif_to_findings``. dependency-cruiser
has **no SARIF reporter** in any version (verified against 17.4.3: ``--output-type
sarif`` errors, no ``src/report/sarif.mjs``; D-14-04 / Pitfall 1), so its native JSON
reporter is the ONLY path. Each ``summary.violations[]`` entry (a circular dep, a
broken/dangling import, a prod→devDep leak) becomes ONE ``architecture_rot`` Finding
citing the offending ``from`` / ``to`` modules + the full cycle chain.

The map MIRRORS the Evidence/Finding construction shape of
``adapters/cicd/actionlint_json.py`` (the thin JSON→Finding analog — it does NOT
import or reuse ``sarif/parser.py``), reading dependency-cruiser's native JSON keys
pinned by ``tests/adapters/architecture/fixtures/dependency-cruiser/sample.json``.

Every Finding is:
  * ``dimension="architecture_rot"`` — D-14-02 (circular deps / broken imports).
  * ``severity``                    — faithful from ``rule.severity`` via
                                       ``_DEPCRUISE_SEVERITY`` (error→major /
                                       warn→minor / info→info). ``error`` tops at
                                       ``major``, so the SCH-04 candidate cap
                                       (which bites only at critical/blocker) is
                                       NEVER tripped — no demotion ever occurs.
  * ``evidence_type="static"``      — SAFE-01: a static graph analysis, never runtime.
  * ``confidence="candidate"``      — D-06-03; Phase 17 corroboration promotes.
  * ``source_tool="dependency-cruiser"``
  * ``rule_id=<rule.name>``         — ``no-circular`` / ``not-to-unresolvable`` / …
  * ``file=<violation.from>``       — the offending source module.

``evidence.output_snippet`` is the cycle chain (``" -> ".join(c["name"] …)``);
``evidence.parsed_value`` carries the full diagnostic payload (rule_name,
rule_severity, type, from, to, cycle names, faithful_severity).

Recommendations use VERIFY-phrasing (the knip ``_CANDIDATE_RECOMMENDATION`` style):
they say "verify" and NEVER carry a runtime-certainty word (enforced/secure/
protected), so the shared CRIT-4 ``assert_verify_phrasing`` tripwire does not raise.

A violation whose ``rule.severity`` is not in the map falls back to the documented
default (``info``) rather than raising. An empty ``summary.violations[]`` → ``[]``.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "dependency-cruiser"
_DEFAULT_DIMENSION = "architecture_rot"

# Faithful dependency-cruiser severity → 7-dimension Severity (RESEARCH line 421).
# ``error`` tops at ``major`` — allowed at confidence='candidate' (SCH-04 caps only
# critical/blocker), so no demotion ever occurs (same as actionlint's flat 'minor').
_DEPCRUISE_SEVERITY: dict[str, str] = {
    "error": "major",
    "warn": "minor",
    "info": "info",
}

# A rule.severity not in the map falls back here rather than raising (documented).
_FALLBACK_SEVERITY = "info"

# Verify-phrasing recommendation (knip _CANDIDATE_RECOMMENDATION style; SC3 / SAFE-05).
# Says "verify"; carries NO runtime-certainty word (enforced/secure/protected) so the
# CRIT-4 assert_verify_phrasing tripwire never raises.
_CANDIDATE_RECOMMENDATION: str = (
    "Architecture violation reported by dependency-cruiser — verify the cited "
    "module chain (from -> to) by inspecting the imports before refactoring; the "
    "tool flags structural shape, not runtime behavior."
)


def depcruise_summary_to_findings(
    violations: list[dict[str, Any]],
    *,
    default_dimension: str = _DEFAULT_DIMENSION,
    severity_map: dict[str, str] | None = None,
) -> list[Finding]:
    """Map ``summary.violations[]`` to architecture_rot Findings (one per entry).

    Args:
        violations: the parsed ``summary.violations`` array. Each entry is a dict
            with ``type`` / ``from`` / ``to`` / ``rule`` (``{severity, name}``) /
            ``cycle`` (``[{name, dependencyTypes}, …]``). An empty list → ``[]``.
        default_dimension: the routed dimension (``architecture_rot`` by default;
            resolved from ``adapter.yaml`` by the caller).
        severity_map: optional CALL-time override of the faithful
            ``{error,warn,info}`` → Severity map. When ``None``, the parser-internal
            ``_DEPCRUISE_SEVERITY`` is used. A ``rule.severity`` not present in the
            effective map falls back to ``info`` (no raise).

    Returns:
        One candidate/static Finding per violation, citing ``from`` / ``to`` /
        ``cycle``. Recommendations pass ``assert_verify_phrasing``.
    """
    effective_map = severity_map if severity_map else _DEPCRUISE_SEVERITY
    findings: list[Finding] = []
    for v in violations:
        rule = v.get("rule") or {}
        rule_name = rule.get("name") or ""
        rule_severity = rule.get("severity") or ""
        # Faithful severity preserved; documented info fallback rather than a raise.
        severity = effective_map.get(rule_severity, _FALLBACK_SEVERITY)

        v_from = v.get("from")
        v_to = v.get("to")
        v_type = v.get("type") or ""
        cycle_names = [
            c.get("name")
            for c in (v.get("cycle") or [])
            if isinstance(c, dict) and c.get("name") is not None
        ]

        # The offending dependency chain — cited verbatim in the report table cell.
        chain = " -> ".join(cycle_names) if cycle_names else (v_to or "")

        evidence = Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=chain,
            parsed_value={
                "rule_name": rule_name,
                "rule_severity": rule_severity,
                "type": v_type,
                "from": v_from,
                "to": v_to,
                "cycle": cycle_names,
                "faithful_severity": severity,
            },
        )
        findings.append(
            Finding(
                dimension=default_dimension,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                file=v_from,
                line=None,
                evidence=evidence,
                evidence_type="static",
                confidence="candidate",
                recommendation=_CANDIDATE_RECOMMENDATION,
                source_tool=_SOURCE_TOOL,
                rule_id=rule_name,
                confidence_caveat=None,
            )
        )
    return findings


def map_depcruise_json(
    doc: dict[str, Any],
    *,
    default_dimension: str = _DEFAULT_DIMENSION,
    severity_map: dict[str, str] | None = None,
) -> list[Finding]:
    """Map a full dependency-cruiser JSON document to Findings.

    Reads ``doc["summary"]["violations"]`` (the only part of the reporter output
    the architecture adapter consumes — the ``modules`` array is ignored) and
    delegates to :func:`depcruise_summary_to_findings`. A missing/empty
    ``summary.violations`` → ``[]`` (the count lives in ``summary.{error,warn,info}``).
    """
    violations = ((doc or {}).get("summary") or {}).get("violations") or []
    return depcruise_summary_to_findings(
        violations,
        default_dimension=default_dimension,
        severity_map=severity_map,
    )


__all__ = [
    "depcruise_summary_to_findings",
    "map_depcruise_json",
]
