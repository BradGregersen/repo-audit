"""SC3 — Python-computed web/RN bundle-size trend deltas (Plan 15-04, Task 1).

The Phase-15 SC3 contract: a bundle-size growth vs the prior scan is a REAL,
Python-computed delta (current − prior), separable from the code-delta
(``loc_delta``), and NEVER invented by the LLM. SAFE-04/08 honesty: a delta is
``None`` (n/a) — NEVER a fabricated ``0`` — when either side's size carrier is
absent / unavailable (a baseline run, or a scan with no web/RN surface).

Carriers (Plan 15-03):
  * lighthouse: ``source_tool="lighthouse"`` Finding,
    ``parsed_value["web_transfer_bytes"]``.
  * RN bundle:  ``source_tool="metro"`` Finding,
    ``parsed_value["rn_bundle_bytes"]`` (the plan's interfaces note named the
    literal "rn-bundle"; the SHIPPED Plan-03 carrier is "metro" — confirmed
    against 15-03 rn_bundle_json.py).

Both deltas must also flow into ``build_allowed_numbers`` (signed AND abs) plus
the prior totals so the agent's "grew from X to Y (+D)" sentence survives the
faithfulness gate.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from repo_audit.render.faithfulness import build_allowed_numbers
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.schema.scope_ledger import ScopeLedger
from repo_audit.trend.delta import compute_trend


def _meta(scan_date: date) -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=scan_date,
        tool_version="0.0.0-test",
    )


def _lighthouse_finding(web_transfer_bytes: int) -> Finding:
    """The lighthouse_perf_summary carrier (source_tool=lighthouse)."""
    return Finding(
        dimension="quality",
        severity="info",
        evidence_type="runtime",
        confidence="candidate",
        source_tool="lighthouse",
        source_collector="quality_depth",
        rule_id="lighthouse_perf_summary",
        recommendation="verify the transfer size against a warm-cache repeat run",
        evidence=Evidence(
            tool="lighthouse",
            parsed_value={"web_transfer_bytes": web_transfer_bytes},
        ),
    )


def _lighthouse_unavailable() -> Finding:
    """A lighthouse carrier stamped evidence_type=unavailable (n/a, not 0)."""
    return Finding(
        dimension="quality",
        severity="info",
        evidence_type="unavailable",
        confidence="candidate",
        source_tool="lighthouse",
        source_collector="quality_depth",
        rule_id="lighthouse_perf_summary",
        recommendation="verify once a live URL is configured",
        evidence=Evidence(
            tool="lighthouse",
            parsed_value={"reason": "no live_url configured"},
        ),
    )


def _rn_bundle_finding(rn_bundle_bytes: int) -> Finding:
    """The rn_bundle_size_summary carrier (source_tool=metro)."""
    return Finding(
        dimension="quality",
        severity="info",
        evidence_type="static",
        confidence="candidate",
        source_tool="metro",
        source_collector="quality_depth",
        rule_id="rn_bundle_size_summary",
        recommendation="verify against your release artifact before acting",
        evidence=Evidence(
            tool="metro",
            parsed_value={"rn_bundle_bytes": rn_bundle_bytes},
        ),
    )


def _loc_finding(total_lines: int) -> Finding:
    return Finding(
        dimension="quality",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="scc",
        source_collector="loc_inventory",
        evidence=Evidence(tool="scc", parsed_value={"total_lines": total_lines}),
    )


def test_web_and_rn_deltas_current_minus_prior(fake_repo):
    """(a) both sides present → delta == current − prior; admitted to the gate."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(
        meta=_meta(date(2026, 5, 1)),
        findings=[_lighthouse_finding(250000), _rn_bundle_finding(400000)],
    )
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[_lighthouse_finding(300000), _rn_bundle_finding(450000)],
    )

    delta = compute_trend(prior, current, repo)

    assert delta.web_transfer_size_delta == 50000
    assert delta.rn_bundle_size_delta == 50000
    # prior totals carry the "from X" half (only when prior present).
    assert delta.prior_totals["web_transfer"] == 250000
    assert delta.prior_totals["rn_bundle"] == 400000

    allowed = build_allowed_numbers([], ScopeLedger(), current.meta, trend=delta)
    # Both signed deltas + their abs values pass the gate.
    assert 50000.0 in allowed
    # The prior absolute totals (the "from X") pass too.
    assert 250000.0 in allowed
    assert 400000.0 in allowed


def test_baseline_run_yields_none_not_zero(fake_repo):
    """(b) prior absent (baseline) → both deltas None, never fabricated 0."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(meta=_meta(date(2026, 5, 1)), findings=[])  # no carrier
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[_lighthouse_finding(300000), _rn_bundle_finding(450000)],
    )

    delta = compute_trend(prior, current, repo)

    assert delta.web_transfer_size_delta is None
    assert delta.rn_bundle_size_delta is None
    # No prior totals when the prior side is absent (omit, never fake 0).
    assert "web_transfer" not in delta.prior_totals
    assert "rn_bundle" not in delta.prior_totals


def test_current_unavailable_carrier_yields_none(fake_repo):
    """(c) current carrier evidence_type=='unavailable' → that delta is None."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(
        meta=_meta(date(2026, 5, 1)),
        findings=[_lighthouse_finding(250000)],
    )
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[_lighthouse_unavailable()],  # current side n/a
    )

    delta = compute_trend(prior, current, repo)

    assert delta.web_transfer_size_delta is None
    # The prior side WAS present → its total is still carried (the "from X").
    assert delta.prior_totals["web_transfer"] == 250000


def test_size_deltas_independent_of_loc_delta(fake_repo):
    """(d) a loc change with no size carrier → size deltas None, loc unaffected."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(meta=_meta(date(2026, 5, 1)), findings=[_loc_finding(5000)])
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)), findings=[_loc_finding(5300)]
    )

    delta = compute_trend(prior, current, repo)

    # Code-delta is computed; size deltas are independent (no size carrier).
    assert delta.loc_delta == 300
    assert delta.web_transfer_size_delta is None
    assert delta.rn_bundle_size_delta is None


def test_prior_totals_omitted_when_prior_size_absent(fake_repo):
    """(e) prior_totals carry the size keys ONLY when the prior value was present."""
    repo = fake_repo({"src/a.ts": "x\n"})
    # Prior has web but NOT rn; current has both.
    prior = ScanReport(
        meta=_meta(date(2026, 5, 1)),
        findings=[_lighthouse_finding(250000)],
    )
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[_lighthouse_finding(300000), _rn_bundle_finding(450000)],
    )

    delta = compute_trend(prior, current, repo)

    assert delta.prior_totals["web_transfer"] == 250000
    assert "rn_bundle" not in delta.prior_totals  # no prior rn → omitted
    # web delta computed, rn delta None (prior rn missing).
    assert delta.web_transfer_size_delta == 50000
    assert delta.rn_bundle_size_delta is None
