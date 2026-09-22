"""SYN-02 — `top_findings` is additive on AgentScanReport; schema_version stays "1".

Covers the schema extension: a `TopFinding` model plus the `top_findings` field
on `AgentScanReport`. `importorskip` guards the synthesis.topfinding module so
this file skips cleanly in a build where that optional module is not present.
"""
from __future__ import annotations

import pytest

_topfinding = pytest.importorskip(
    "repo_audit.synthesis.topfinding",
    reason="optional module repo_audit.synthesis.topfinding not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.agent.schema import AgentScanReport, TopFinding
from repo_audit.schema.report import ScanReport


def test_additive_forward_compatible():
    """A populated TopFinding round-trips; a report WITHOUT top_findings validates."""
    tf = TopFinding(
        rank=1,
        finding_ref="osv-scanner::CVE-X::pkg/a.ts:10",
        file="pkg/a.ts",
        line=10,
        severity="critical",
        confidence="confirmed",
        composite=0.62,
        band=1,
        dominant_driver="exploitability",
        why_it_matters="",
    )
    dumped = tf.model_dump()
    again = TopFinding.model_validate(dumped)
    assert again == tf

    # A populated report round-trips.
    report = AgentScanReport(top_findings=[tf], executive_summary="x")
    round_tripped = AgentScanReport.model_validate_json(report.model_dump_json())
    assert round_tripped.top_findings == [tf]

    # ADDITIVE: a report JSON WITHOUT top_findings still validates (default []).
    legacy = AgentScanReport.model_validate({"executive_summary": "legacy"})
    assert legacy.top_findings == []

    # schema_version stays "1" — the additive field does NOT bump it.
    sr = ScanReport.model_validate(
        {
            "schema_version": "1",
            "meta": {
                "repo_slug": "r",
                "commit_sha": "UNCOMMITTED",
                "scan_date": "2026-06-05",
                "tool_version": "0.0.0-test",
            },
            "findings": [],
            "scope_ledger": {"scanned": [], "skipped": [], "unavailable": []},
        }
    )
    assert sr.schema_version == "1"


def test_topfinding_forbids_unknown_field_and_defaults_prose():
    """extra='forbid' rejects an unknown field; why_it_matters defaults to ''."""
    tf = TopFinding(
        rank=2,
        finding_ref="ruff::E501::src/x.py:3",
        severity="major",
        confidence="corroborated",
        composite=0.31,
    )
    assert tf.why_it_matters == ""
    with pytest.raises(Exception):
        TopFinding(
            rank=2,
            finding_ref="ruff::E501::src/x.py:3",
            severity="major",
            confidence="corroborated",
            composite=0.31,
            smuggled_rank=99,  # type: ignore[call-arg]
        )


def test_build_top_findings_python_authors_ranking(finding_factory):
    """build_top_findings authors rank/ids/score; why_it_matters left empty."""
    from repo_audit.synthesis.record import PriorityScore

    f0 = finding_factory(severity="critical", confidence="confirmed",
                         file="a.ts", line=5, rule_id="R1", source_tool="osv")
    f1 = finding_factory(severity="major", confidence="corroborated",
                         file="b.ts", line=9, rule_id="R2", source_tool="ruff")
    s0 = PriorityScore(candidate_token=0, composite=0.7, band=1,
                       dominant_driver="exploitability")
    s1 = PriorityScore(candidate_token=1, composite=0.4, band=0,
                       dominant_driver="severity")
    data = [(0, f0, s0), (1, f1, s1)]

    tops = _topfinding.build_top_findings(data)
    assert [t.rank for t in tops] == [1, 2]
    assert tops[0].finding_ref == "osv::R1::a.ts:5"
    assert tops[0].composite == 0.7
    assert tops[0].band == 1
    assert tops[0].dominant_driver == "exploitability"
    assert all(t.why_it_matters == "" for t in tops)


def test_build_top_findings_tolerates_missing_score(finding_factory):
    """A None PriorityScore yields neutral magnitudes — the item still links."""
    f = finding_factory(file="c.ts", line=1, rule_id="R", source_tool="t")
    tops = _topfinding.build_top_findings([(0, f, None)])
    assert tops[0].composite == 0.0
    assert tops[0].band == 0
    assert tops[0].finding_ref == "t::R::c.ts:1"
