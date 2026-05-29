"""SAFE-06, D-69 — render-time corroboration check (Plan 04-08 Task 1).

These test bodies were filled by Plan 04-08 (the stubs landed in Wave 0).
The importorskip gate flips ACTIVE once render/corroboration.py exists.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_corroborated_when_two_tools             (SAFE-06/D-69 — corroborated when 2 tools agree)
- test_uncorroborated_with_caveat_render_class (D-69 — uncorroborated → caveat render class)
- test_render_classes                          (D-69 — 2x2 render-class grid)
- test_agent_dispute_logged                    (D-69 — meta.agent_corroboration_disputes)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.corroboration",
    reason="Wave 1+ plan 04-07 has not landed yet — Wave 0 stub.",
)

from repo_audit.agent.schema import (  # noqa: E402
    AgentScanReport,
    DimensionNarrative,
    SeverityCall,
)
from repo_audit.render.corroboration import (  # noqa: E402
    classify_critical_finding,
    detect_corroboration_disputes,
    is_corroborated,
)
from repo_audit.schema.finding import Evidence, Finding  # noqa: E402


def _finding(
    *,
    source_tool: str,
    dimension: str = "security",
    file: str = "src/a.ts",
    line: int = 10,
    severity: str = "critical",
    confidence: str = "corroborated",
    rule_id: str = "R1",
    confidence_caveat: str | None = "runtime not verified",
) -> Finding:
    return Finding(
        dimension=dimension,
        severity=severity,
        file=file,
        line=line,
        evidence=Evidence(tool=source_tool),
        evidence_type="static",
        confidence=confidence,
        rule_id=rule_id,
        source_tool=source_tool,
        confidence_caveat=confidence_caveat,
    )


def test_corroborated_when_two_tools():
    """SAFE-06/D-69: a finding is corroborated when two tools agree."""
    f1 = _finding(source_tool="tsc", rule_id="R1")
    f2 = _finding(source_tool="eslint", rule_id="R2")
    all_findings = [f1, f2]
    assert is_corroborated(f1, all_findings) is True
    assert is_corroborated(f2, all_findings) is True


def test_uncorroborated_with_caveat_render_class():
    """D-69: an uncorroborated finding uses the caveat render class."""
    f1 = _finding(source_tool="tsc", confidence_caveat="runtime not verified")
    render_class = classify_critical_finding(f1, [f1])
    assert render_class == "critical-uncorroborated-with-caveat"


def test_render_classes():
    """D-69: the 2x2 render-class grid resolves correctly."""
    # (corroborated, has_caveat) → critical-corroborated
    fc_a = _finding(source_tool="tsc", file="x.ts", confidence_caveat="caveat")
    fc_b = _finding(source_tool="eslint", file="x.ts", confidence_caveat="caveat")
    assert classify_critical_finding(fc_a, [fc_a, fc_b]) == "critical-corroborated"

    # (corroborated, no_caveat) → critical-corroborated
    # critical+static would reject a missing caveat, so use a runtime finding.
    fd_a = Finding(
        dimension="security", severity="critical", file="y.ts", line=1,
        evidence=Evidence(tool="tsc"), evidence_type="runtime",
        confidence="corroborated", rule_id="A", source_tool="tsc",
        confidence_caveat=None,
    )
    fd_b = Finding(
        dimension="security", severity="critical", file="y.ts", line=1,
        evidence=Evidence(tool="eslint"), evidence_type="runtime",
        confidence="corroborated", rule_id="B", source_tool="eslint",
        confidence_caveat=None,
    )
    assert classify_critical_finding(fd_a, [fd_a, fd_b]) == "critical-corroborated"

    # (not_corroborated, has_caveat) → critical-uncorroborated-with-caveat
    fe = _finding(source_tool="tsc", file="z.ts", confidence_caveat="caveat")
    assert classify_critical_finding(fe, [fe]) == "critical-uncorroborated-with-caveat"

    # (not_corroborated, no_caveat) → critical-uncorroborated-fallthrough
    ff = Finding(
        dimension="security", severity="critical", file="w.ts", line=1,
        evidence=Evidence(tool="tsc"), evidence_type="runtime",
        confidence="corroborated", rule_id="C", source_tool="tsc",
        confidence_caveat=None,
    )
    assert classify_critical_finding(ff, [ff]) == "critical-uncorroborated-fallthrough"


def test_agent_dispute_logged():
    """D-69: agent disputes are logged to meta.agent_corroboration_disputes."""
    # Single-tool finding → deterministic is_corroborated == False.
    f1 = _finding(source_tool="tsc", rule_id="R1", file="src/a.ts", line=10)
    finding_ref = "tsc::R1::src/a.ts:10"
    agent_output = AgentScanReport(
        dimensions=[
            DimensionNarrative(
                dimension="security",
                narrative="Auth has issues.",
                severity_calls=[
                    SeverityCall(
                        finding_ref=finding_ref,
                        agent_severity="critical",
                        corroborated_by=["tsc"],
                    )
                ],
            )
        ],
        executive_summary="",
    )
    disputes = detect_corroboration_disputes(agent_output, [f1])
    assert len(disputes) == 1
    entry = disputes[0]
    assert entry["finding_ref"] == finding_ref
    assert entry["agent_claim"] == ["tsc"]
    assert entry["deterministic_result"] is False
