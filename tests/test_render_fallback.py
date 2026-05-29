"""D-67 — agent-unavailable fallback rendering (Plan 04-08 Task 2).

These test bodies were filled by Plan 04-08 (the stubs landed in Wave 0).
The skip guard on ReportMeta.agent_status keeps the contract pinned.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_fallback_dimensions_render_pending   (D-67 — meta.agent_status='unavailable_*' → dims render D-09 pending)
- test_fallback_exec_summary_renders_pending (D-67 — exec summary renders pending)
- test_fallback_exit_code_zero               (D-67 — exit 0 honesty contract)
"""
from __future__ import annotations

from datetime import date

import pytest


def _agent_status_field_landed() -> bool:
    """True once the agent meta-capture plan adds ReportMeta.agent_status."""
    from repo_audit.schema.report import ReportMeta

    return "agent_status" in ReportMeta.model_fields


pytestmark = pytest.mark.skipif(
    not _agent_status_field_landed(),
    reason="agent meta-capture plan has not landed yet (ReportMeta.agent_status absent) — Wave 0 stub.",
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


def test_fallback_dimensions_render_pending(tmp_path):
    """D-67: meta.agent_status='unavailable_*' → each dimension renders the pending marker."""
    from repo_audit.render import renderer as renderer_mod

    scan_report = _scan_report(agent_status="unavailable_network")
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(scan_report, md_path, json_path, agent_output=None)
    assert rc == 0
    md = md_path.read_text(encoding="utf-8")
    # The D-67 per-dimension fallback marker names the agent_status.
    assert "AI narrative unavailable" in md
    assert "unavailable_network" in md


def test_fallback_exec_summary_renders_pending(tmp_path):
    """D-67: the executive summary renders the pending marker on fallback."""
    from repo_audit.render import renderer as renderer_mod

    scan_report = _scan_report(agent_status="unavailable_network")
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(scan_report, md_path, json_path, agent_output=None)
    assert rc == 0
    md = md_path.read_text(encoding="utf-8")
    # Deterministic header is always present (built from findings).
    assert "blocker," in md and "critical finding(s)" in md
    # Exec summary fallback marker.
    assert "Unable to curate executive summary" in md


def test_fallback_exit_code_zero(tmp_path):
    """D-67: the exit code is 0 on agent-unavailable fallback (honesty contract)."""
    from repo_audit.render import renderer as renderer_mod

    scan_report = _scan_report(agent_status="unavailable_sdk_exception")
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(scan_report, md_path, json_path, agent_output=None)
    assert rc == 0
