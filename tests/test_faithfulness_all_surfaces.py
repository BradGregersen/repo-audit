"""Render-level proof that every agent prose surface is number-gated.

The faithfulness gate must cover all four places agent-authored prose reaches a
written report: each dimension narrative, the executive summary, the trend
narrative, and every Top-N ``why_it_matters`` sentence. A fabricated number in
any of them is stripped before the report is written and recorded in
``meta.faithfulness_violations``; a sentence citing a number that IS traceable
to the collected evidence survives verbatim.
"""
from __future__ import annotations

import json
from datetime import date

import pytest

pytest.importorskip("claude_agent_sdk", reason="agent schema requires the SDK")

FABRICATED = "987654"

EXEC_KEEP = "The auth module has 3 open items."
EXEC_BAD = f"The scan touched {FABRICATED} files."
TREND_KEEP = "Commits rose by 14 since the prior report."
TREND_BAD = f"Churn grew to {FABRICATED} lines."
WHY_KEEP = "This is ranked 1 because it is reachable."
WHY_BAD = f"It affects {FABRICATED} users."
DIM_KEEP = "Quality looks steady with 2 concerns."
DIM_BAD = f"There are {FABRICATED} lint problems."


def _render(tmp_path):
    from repo_audit.agent.schema import (
        AgentScanReport,
        DimensionNarrative,
        TopFinding,
    )
    from repo_audit.render.renderer import render_and_write
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger
    from repo_audit.schema.trend import TrendDelta

    meta = ReportMeta(
        repo_slug="example-app",
        commit_sha="abc1234",
        scan_date=date(2026, 9, 23),
        tool_version="0.1.0",
        agent_status="ok",
        baseline_run=False,
    )
    scan_report = ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())
    trend = TrendDelta(
        prior_baseline_date=date(2026, 9, 1),
        commits_delta=14,
        prior_totals={"commits": 120},
    )
    top = [
        TopFinding(
            rank=1,
            finding_ref="semgrep::rule-x::src/a.py:10",
            file="src/a.py",
            line=10,
            severity="critical",
            confidence="high",
            composite=0.62,
            why_it_matters=f"{WHY_KEEP} {WHY_BAD}",
        )
    ]
    agent_output = AgentScanReport(
        dimensions=[
            DimensionNarrative(
                dimension="quality",
                narrative=f"{DIM_KEEP} {DIM_BAD}",
                severity_calls=[],
            )
        ],
        executive_summary=f"{EXEC_KEEP} {EXEC_BAD}",
        trend_narrative=f"{TREND_KEEP} {TREND_BAD}",
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = render_and_write(
        scan_report,
        md_path,
        json_path,
        agent_output=agent_output,
        trend=trend,
        top_findings=top,
    )
    assert rc == 0
    return scan_report, md_path.read_text(), json.loads(json_path.read_text())


def test_fabricated_number_stripped_from_every_surface(tmp_path):
    _, md, _ = _render(tmp_path)
    assert FABRICATED not in md


def test_traceable_sentences_survive_verbatim(tmp_path):
    _, md, _ = _render(tmp_path)
    for sentence in (EXEC_KEEP, TREND_KEEP, WHY_KEEP, DIM_KEEP):
        assert sentence in md, f"traceable sentence was stripped: {sentence!r}"


@pytest.mark.parametrize(
    "bad_sentence", [EXEC_BAD, TREND_BAD, WHY_BAD, DIM_BAD],
    ids=["executive_summary", "trend_narrative", "why_it_matters", "dimension"],
)
def test_each_surface_records_a_violation(tmp_path, bad_sentence):
    scan_report, _, sidecar = _render(tmp_path)
    recorded = [v.original_sentence for v in scan_report.meta.faithfulness_violations]
    assert bad_sentence in recorded, recorded
    # The same record reaches the JSON sidecar.
    sidecar_sentences = [
        v["original_sentence"] for v in sidecar["meta"]["faithfulness_violations"]
    ]
    assert bad_sentence in sidecar_sentences


def test_top_findings_gated_without_agent_output(tmp_path):
    """A caller passing top_findings with no agent report is still gated."""
    from repo_audit.agent.schema import TopFinding
    from repo_audit.render.renderer import render_and_write
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    meta = ReportMeta(
        repo_slug="example-app",
        commit_sha="abc1234",
        scan_date=date(2026, 9, 23),
        tool_version="0.1.0",
    )
    scan_report = ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())
    top = [
        TopFinding(
            rank=1,
            finding_ref="semgrep::rule-x::src/a.py:10",
            severity="critical",
            confidence="high",
            composite=0.62,
            why_it_matters=f"{WHY_KEEP} {WHY_BAD}",
        )
    ]
    md_path = tmp_path / "r.md"
    rc = render_and_write(
        scan_report, md_path, tmp_path / "r.json", top_findings=top,
    )
    assert rc == 0
    md = md_path.read_text()
    assert FABRICATED not in md
    assert WHY_KEEP in md
    assert WHY_BAD in [v.original_sentence for v in scan_report.meta.faithfulness_violations]
