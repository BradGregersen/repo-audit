"""axe-core results JSON → one quality Finding per WCAG violation (A11Y-01).

A tiny, dedicated transform — NOT a fork of ``sarif_to_findings`` (axe emits no
SARIF). The axe-core results document carries a ``violations[]`` array; this
module maps each violation to EXACTLY ONE ``quality`` Finding (one-per-violation,
NEVER one-per-node — a single rule that fails on 40 elements is one accessibility
issue, not 40). It MIRRORS the per-message → per-Finding loop shape of
``adapters/typescript/parsers/eslint.py`` and the faithful-severity-in-parsed_value
+ top-N + verify-phrasing discipline of
``adapters/architecture/jscpd_json.py`` (the ``_CANDIDATE_RECOMMENDATION`` model).

Contract (RESEARCH §"Pattern 2"):
  * ``dimension="quality"`` (the PUBLIC dimension token — PATTERNS §Dimension
    token; the adapter.yaml block-level ``quality_debt`` is the routing default,
    the maps construct the public ``quality`` per-Finding).
  * Severity ladder: ``critical``/``serious`` → ``major``; ``moderate`` →
    ``minor``; ``minor`` → ``info``. The ladder TOPS at ``major``, so the SCH-04
    candidate cap (which bites only at critical/blocker) is NEVER tripped — the
    faithful axe impact is preserved verbatim in ``parsed_value['faithful_impact']``.
  * ``evidence_type="runtime"`` (a live headless-Chrome page load — the deep web
    a11y tier), ``confidence="candidate"`` (D-06-03; Phase 17 corroboration is
    the SOLE promotion path — ``runtime`` is orthogonal to confidence and does
    NOT promote, D-15-07), ``file=None``, ``line=None``, ``source_tool="axe-core"``.
  * REDACTION (T-15-04): raw ``node.html`` rendered page markup NEVER enters the
    Finding. Only the rule's help text + ``helpUrl`` reach ``output_snippet``;
    only a bounded ``node_targets`` CSS-selector list (≤ TOP_N) + the full
    ``node_count`` reach ``parsed_value``.
  * VERIFY-PHRASING (D-15-07 runtime-exemption trap): the recommendation CONTAINS
    "verify" and contains NONE of ``enforced`` / ``secure`` / ``protected``. This
    is SELF-ENFORCED here — the shared CRIT-4 ``assert_verify_phrasing`` tripwire
    EXEMPTS ``evidence_type == "runtime"``, so it would silently pass an
    overclaiming axe finding; this module must police itself, so it does NOT call
    ``assert_verify_phrasing``.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "axe-core"
_SOURCE_COLLECTOR = "quality_depth"
_DEFAULT_DIMENSION = "quality"
_RULE_ID_FALLBACK = "axe_violation"

# Cap on the CSS-selector node targets cited inside a violation's parsed_value.
# The full node count is always preserved separately (node_count).
_TOP_N_NODES = 10

# Faithful axe-impact → severity rung. The ladder TOPS at ``major`` so a
# candidate runtime finding can never request critical/blocker (SCH-04 safe).
_SEVERITY_BY_IMPACT: dict[str, str] = {
    "critical": "major",
    "serious": "major",
    "moderate": "minor",
    "minor": "info",
}

# Verify-phrasing recommendation (jscpd ``_CANDIDATE_RECOMMENDATION`` style;
# SC3 / SAFE-05). Says "verify"; carries NO runtime-certainty word
# (enforced/secure/protected). Self-enforced because the shared CRIT-4 tripwire
# exempts runtime findings (the D-15-07 trap).
_CANDIDATE_RECOMMENDATION: str = (
    "axe-core reported this WCAG violation on a live page load — verify the "
    "cited element selectors against the rule's help guidance and confirm the "
    "fix in the rendered UI; axe flags machine-detectable accessibility "
    "barriers, not the full manual audit surface."
)


def _axe_severity(impact: Any) -> str:
    """Map a faithful axe impact band to a severity rung.

    ``critical``/``serious`` → ``major``; ``moderate`` → ``minor``; ``minor`` →
    ``info``. An unknown / missing impact degrades to ``info`` — it NEVER
    promotes (an unrecognized band must not be louder than a known one). The
    ladder tops at ``major`` so the SCH-04 candidate cap is never tripped.
    """
    if not isinstance(impact, str):
        return "info"
    return _SEVERITY_BY_IMPACT.get(impact.lower(), "info")


def _node_targets(nodes: list[dict[str, Any]], top_n: int) -> list[Any]:
    """The bounded CSS-selector target list from a violation's nodes.

    Each axe node's ``target`` is a CSS-selector list locating the offending
    element. We cite the first ``top_n`` of them — NEVER the raw ``node.html``
    page markup (T-15-04 redaction). The full node count is preserved by the
    caller in ``node_count``.
    """
    targets: list[Any] = []
    for node in nodes[: max(top_n, 0)]:
        if isinstance(node, dict) and "target" in node:
            targets.append(node["target"])
    return targets


def map_axe_json(
    report: dict[str, Any],
    *,
    default_dimension: str = _DEFAULT_DIMENSION,
    top_n: int = _TOP_N_NODES,
) -> list[Finding]:
    """Map an axe-core results document to one quality Finding per violation.

    Args:
        report: the parsed axe results JSON
            (``{url, violations:[{id, impact, tags, help, helpUrl, nodes:[...]}]}``).
        default_dimension: the routed dimension (``quality`` by default — the
            PUBLIC dimension token; resolved from ``adapter.yaml`` by the caller).
        top_n: cap on the cited node CSS-selector targets per violation
            (default 10). The full node count is always preserved.

    Returns:
        A list with EXACTLY ONE runtime/candidate ``quality`` Finding per
        ``violations[]`` entry (one-per-violation, NEVER one-per-node). An empty
        / missing ``violations`` array → ``[]``. NEVER raises across the boundary.
    """
    violations = (report or {}).get("violations") or []
    findings: list[Finding] = []
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        rule_id = violation.get("id") or _RULE_ID_FALLBACK
        impact = violation.get("impact")
        severity = _axe_severity(impact)
        nodes = violation.get("nodes") or []
        help_text = violation.get("help") or ""
        help_url = violation.get("helpUrl") or ""

        # REDACTION (T-15-04): only help text + helpUrl reach the snippet —
        # the raw node.html page markup is deliberately excluded.
        snippet = f"{help_text} ({help_url})".strip()

        evidence = Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=snippet,
            parsed_value={
                "rule_id": rule_id,
                "faithful_impact": impact,
                "wcag_tags": violation.get("tags") or [],
                "node_targets": _node_targets(nodes, top_n),
                "node_count": len(nodes),
                "help_url": help_url,
            },
        )
        findings.append(
            Finding(
                dimension=default_dimension,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                file=None,
                line=None,
                evidence=evidence,
                evidence_type="runtime",
                confidence="candidate",
                recommendation=_CANDIDATE_RECOMMENDATION,
                source_tool=_SOURCE_TOOL,
                source_collector=_SOURCE_COLLECTOR,
                rule_id=rule_id,
                confidence_caveat=None,
            )
        )
    return findings


# Alias: the runtime-verify-phrasing scaffold (test_runtime_verify_phrasing.py)
# calls ``map_axe_violations`` — the same per-violation entry point under a name
# that reads as "one finding per violation". Kept in lockstep with map_axe_json.
map_axe_violations = map_axe_json


__all__ = [
    "map_axe_json",
    "map_axe_violations",
    "_axe_severity",
]
