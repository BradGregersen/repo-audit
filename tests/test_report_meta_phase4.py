"""Plan 04-03 — ReportMeta Phase 4 additive extension (D-65, D-67, D-69, D-70).

These tests pin the additive-extension contract:
- AgentStatus Literal covers exactly the 6 D-67 states.
- ReportMeta gains 7 Optional fields; every Phase 1/2/3 callsite still works.
- schema_version stays "1" (D-21 — additive changes are NOT a version bump).
- A Phase 3 JSON sidecar (no Phase 4 fields) round-trip-validates.

RED-first: this file is written before enums.py / report.py are extended.
"""
from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from repo_audit.schema import ReportMeta, ScanReport
from repo_audit.schema.enums import AgentStatus

_D67_STATES = (
    "ok",
    "unavailable_auth_missing",
    "unavailable_network",
    "unavailable_emit_report_invalid",
    "unavailable_sdk_exception",
    "cost_capped",
)


def _phase3_meta() -> ReportMeta:
    """Phase 1/2/3 callsite shape — no Phase 4 fields specified."""
    return ReportMeta(
        repo_slug="x",
        commit_sha="abc",
        scan_date=date.today(),
        tool_version="0.1.0",
    )


def test_agent_status_literal_accepts_all_six_states():
    """AgentStatus validates each of the 6 D-67 values via ReportMeta."""
    for state in _D67_STATES:
        m = ReportMeta(
            repo_slug="x",
            commit_sha="abc",
            scan_date=date.today(),
            tool_version="0.1.0",
            agent_status=state,
        )
        assert m.agent_status == state


@pytest.mark.parametrize("bogus", ["failed", "partial", "in_progress", "OK", ""])
def test_agent_status_literal_rejects_unknown_values(bogus):
    """AgentStatus REJECTS any value outside the 6-state taxonomy."""
    with pytest.raises(ValidationError) as exc:
        ReportMeta(
            repo_slug="x",
            commit_sha="abc",
            scan_date=date.today(),
            tool_version="0.1.0",
            agent_status=bogus,
        )
    msg = str(exc.value).lower()
    assert "agent_status" in msg or "literal" in msg


def test_phase3_callsite_still_constructs_without_phase4_fields():
    """Phase 1/2/3 callsites must not need updating — defaults apply."""
    m = _phase3_meta()
    assert m.agent_status is None
    assert m.total_cost_usd is None
    assert m.token_usage is None
    assert m.wall_clock_seconds is None
    assert m.faithfulness_violations == []
    assert m.exec_summary_dilution_strips == []
    assert m.agent_corroboration_disputes == []


def test_full_phase4_population_via_model_validate():
    """model_validate accepts all 7 new fields when populated."""
    payload = {
        "repo_slug": "x",
        "commit_sha": "abc",
        "scan_date": date.today().isoformat(),
        "tool_version": "0.1.0",
        "agent_status": "ok",
        "total_cost_usd": 0.0123,
        "token_usage": 12345,
        "wall_clock_seconds": 42.5,
        "faithfulness_violations": [],
        "exec_summary_dilution_strips": ["This had a minor count."],
        "agent_corroboration_disputes": [
            {"finding_ref": "eslint::no-x::a.ts:1", "agent_claim": ["tsc"]}
        ],
    }
    m = ReportMeta.model_validate(payload)
    assert m.agent_status == "ok"
    assert m.total_cost_usd == 0.0123
    assert m.token_usage == 12345
    assert m.wall_clock_seconds == 42.5
    assert m.exec_summary_dilution_strips == ["This had a minor count."]
    assert m.agent_corroboration_disputes[0]["finding_ref"] == "eslint::no-x::a.ts:1"


def test_phase3_sidecar_round_trips_into_extended_meta():
    """A Phase 3 JSON sidecar (no Phase 4 fields) parses cleanly."""
    # Shape a Phase 3 scan would have produced — meta with the original 7 fields only.
    report = ScanReport(meta=_phase3_meta())
    dumped = report.model_dump_json()
    reloaded = ScanReport.model_validate_json(dumped)
    assert reloaded.schema_version == "1"
    assert reloaded.meta.agent_status is None
    assert reloaded.meta.faithfulness_violations == []


def test_schema_version_unchanged_at_one():
    """D-21 — adding 7 fields does NOT bump schema_version."""
    report = ScanReport(meta=_phase3_meta())
    assert report.schema_version == "1"


def test_agent_status_is_mutable_post_construction():
    """No immutability gotcha — the session loop assigns agent_status late."""
    m = _phase3_meta()
    m.agent_status = "cost_capped"
    assert m.agent_status == "cost_capped"


def test_total_cost_usd_accepts_none():
    """total_cost_usd is float | None (None when ResultMessage gave no cost)."""
    m = ReportMeta(
        repo_slug="x",
        commit_sha="abc",
        scan_date=date.today(),
        tool_version="0.1.0",
        agent_status="cost_capped",
        total_cost_usd=None,
        token_usage=999,
    )
    assert m.total_cost_usd is None
    assert m.token_usage == 999
