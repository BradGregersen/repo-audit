"""TREND-01 / TREND-02 — pure-Python trend delta math.

Deltas (commits, LOC, lint-error, coverage, finding-count-by-dimension) are
computed in pure Python from the prior + current ScanReport. The agent never
computes or invents numbers (TREND-02 / D-05-07).

SAFE-04/08 honesty: when a metric is unavailable on either side, the delta is
``None`` (n/a), NEVER a fabricated ``0``.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.trend.delta import compute_trend


def _meta(scan_date: date) -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=scan_date,
        tool_version="0.0.0-test",
    )


def _cadence_finding(commits_total: int) -> Finding:
    return Finding(
        dimension="process",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="pygit2",
        source_collector="git_cadence",
        evidence=Evidence(tool="pygit2", parsed_value={"commits_total": commits_total}),
    )


def _loc_finding(total_lines: int) -> Finding:
    return Finding(
        dimension="quality",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="scc",
        source_collector="loc_inventory",
        evidence=Evidence(
            tool="scc",
            parsed_value={"summary": "top-N largest files", "total_lines": total_lines},
        ),
    )


def _eslint_finding(file: str, line: int, rule_id: str = "no-unused-vars") -> Finding:
    return Finding(
        dimension="quality",
        severity="major",
        file=file,
        line=line,
        evidence_type="static",
        confidence="high",
        source_tool="eslint",
        source_collector="typescript_adapter",
        rule_id=rule_id,
        evidence=Evidence(tool="eslint", parsed_value={"rule_id": rule_id}),
    )


def _lcov_finding(line_pct: float | None) -> Finding:
    """A coverage finding; line_pct=None → unavailable artifact."""
    if line_pct is None:
        return Finding(
            dimension="test_integrity",
            severity="info",
            evidence_type="unavailable",
            confidence="high",
            source_tool="lcov",
            source_collector="typescript_adapter",
            rule_id="coverage_summary",
            evidence=Evidence(
                tool="lcov-parser",
                parsed_value={"reason": "stale_or_missing_coverage_artifact"},
            ),
        )
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="static",
        confidence="high",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_summary",
        confidence_caveat="Coverage from a static lcov.info artifact; runtime not re-executed.",
        evidence=Evidence(
            tool="lcov-parser",
            parsed_value={"total_pct": line_pct, "line_pct": line_pct},
        ),
    )


def test_deltas_python_computed(fake_repo):
    """All five metric families: hand-computed deltas must match compute_trend."""
    repo = fake_repo({"src/a.ts": "x\n", "src/b.ts": "y\n"})

    prior = ScanReport(
        meta=_meta(date(2026, 5, 1)),
        findings=[
            _cadence_finding(100),
            _loc_finding(5000),
            _lcov_finding(60.0),
            _eslint_finding("src/a.ts", 10),
            _eslint_finding("src/a.ts", 20, rule_id="eqeqeq"),
            _eslint_finding("src/b.ts", 5, rule_id="no-console"),
        ],
    )
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[
            _cadence_finding(112),  # +12 commits
            _loc_finding(5300),  # +300 LOC
            _lcov_finding(73.5),  # +13.5 coverage
            _eslint_finding("src/a.ts", 10),  # still present
            # b.ts:5 + a.ts:20 lint errors resolved → lint count 3 → 1 = -2
        ],
    )

    delta = compute_trend(prior, current, repo)

    assert delta.prior_baseline_date == date(2026, 5, 1)
    assert delta.commits_delta == 12
    assert delta.loc_delta == 300
    assert delta.lint_error_delta == -2
    assert delta.coverage_delta is not None
    assert round(delta.coverage_delta, 2) == 13.5
    # finding-count delta by dimension. quality findings are the loc aggregate
    # (1) + the eslint findings: prior=1 loc + 3 eslint = 4; current=1 loc + 1
    # eslint = 2; delta = -2. test_integrity (lcov) 1 → 1 (0); process
    # (git_cadence) 1 → 1 (0).
    assert delta.finding_count_delta_by_dimension["quality"] == -2
    assert delta.finding_count_delta_by_dimension["test_integrity"] == 0
    assert delta.finding_count_delta_by_dimension["process"] == 0
    # All 7 dimensions must be present (exhaustive iteration).
    for dim in (
        "security",
        "architecture_rot",
        "test_integrity",
        "correctness",
        "quality",
        "process",
        "observability",
    ):
        assert dim in delta.finding_count_delta_by_dimension


def test_coverage_unavailable_yields_none_not_zero(fake_repo):
    """SAFE-04/08: coverage unavailable in current → coverage_delta is None, not 0."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(
        meta=_meta(date(2026, 5, 1)),
        findings=[_lcov_finding(60.0)],
    )
    current = ScanReport(
        meta=_meta(date(2026, 5, 28)),
        findings=[_lcov_finding(None)],  # unavailable artifact
    )

    delta = compute_trend(prior, current, repo)

    assert delta.coverage_delta is None


def test_missing_collector_yields_none_delta(fake_repo):
    """A metric absent from both reports → delta None, never fabricated 0."""
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(meta=_meta(date(2026, 5, 1)), findings=[])
    current = ScanReport(meta=_meta(date(2026, 5, 28)), findings=[])

    delta = compute_trend(prior, current, repo)

    assert delta.commits_delta is None
    assert delta.loc_delta is None
    assert delta.coverage_delta is None
    # lint-error delta: zero eslint findings on both sides is a real 0, not a missing metric.
    assert delta.lint_error_delta == 0


def test_prior_baseline_date_is_prior_meta_scan_date(fake_repo):
    repo = fake_repo({"src/a.ts": "x\n"})
    prior = ScanReport(meta=_meta(date(2026, 3, 15)), findings=[_cadence_finding(10)])
    current = ScanReport(meta=_meta(date(2026, 5, 28)), findings=[_cadence_finding(10)])

    delta = compute_trend(prior, current, repo)

    assert delta.prior_baseline_date == date(2026, 3, 15)
