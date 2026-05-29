"""AGENT-06, D-65, D-67 — agent meta footer rendering (Plan 04-08 Task 2).

These test bodies were filled by Plan 04-08 (the stubs landed in Wave 0).
The importorskip gate on the renderer module keeps the contract pinned.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_footer_shows_cost_and_duration       (AGENT-06 — footer shows cost + duration)
- test_footer_shows_token_usage             (AGENT-06/D-65 — footer shows token usage)
- test_footer_shows_agent_status_when_unavailable (D-67 — footer shows agent status when unavailable)
"""
from __future__ import annotations

from datetime import date

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.renderer",
    reason="Wave 1+ (footer-rendering symbols) has not landed yet — Wave 0 stub.",
)


def _scan_report(**meta_overrides):
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    base = dict(
        repo_slug="x",
        commit_sha="abc1234",
        scan_date=date.today(),
        tool_version="0.1.0",
    )
    base.update(meta_overrides)
    meta = ReportMeta(**base)
    return ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())


def test_footer_shows_cost_and_duration(tmp_path):
    """AGENT-06: the report footer shows agent cost and duration."""
    scan_report = _scan_report(
        agent_status="ok",
        total_cost_usd=0.1234,
        wall_clock_seconds=12.5,
        token_usage=42_000,
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = _mod.render_and_write(scan_report, md_path, json_path)
    assert rc == 0
    md = md_path.read_text(encoding="utf-8")
    assert "0.1234" in md
    assert "12.50" in md


def test_footer_shows_token_usage(tmp_path):
    """AGENT-06/D-65: the report footer shows token usage."""
    scan_report = _scan_report(
        agent_status="ok",
        total_cost_usd=0.5,
        wall_clock_seconds=3.0,
        token_usage=1_234_567,
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = _mod.render_and_write(scan_report, md_path, json_path)
    assert rc == 0
    md = md_path.read_text(encoding="utf-8")
    assert "1,234,567" in md


def test_footer_shows_agent_status_when_unavailable(tmp_path):
    """D-67: the footer shows the agent status when unavailable."""
    scan_report = _scan_report(agent_status="unavailable_auth_missing")
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = _mod.render_and_write(scan_report, md_path, json_path)
    assert rc == 0
    md = md_path.read_text(encoding="utf-8")
    assert "unavailable_auth_missing" in md
