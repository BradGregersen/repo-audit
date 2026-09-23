"""Tests for repo_audit.fleet.aggregate (FLEET-02 / SC-6).

Load-bearing proof: the aggregator reads ONLY the JSON sidecar, never the
markdown. test_reads_json_not_md mutates the .md and asserts the FleetSnapshot
is unchanged. Also covers corrupt-sidecar -> failed row (T-05-05) and
None-meta-fields tolerance under --no-agent (RESEARCH Pitfall 5).
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from repo_audit.fleet.aggregate import (
    aggregate,
    build_repo_row,
    make_failed_row,
)
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.fleet import FleetRepoRow
from repo_audit.schema.report import ReportMeta, ScanReport


def _coverage_finding(total_pct: float) -> Finding:
    """An lcov-shaped coverage finding (source_tool/rule_id the aggregator reads)."""
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="static",
        confidence="high",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_summary",
        confidence_caveat="coverage from static lcov artifact; not a live run",
        evidence=Evidence(
            tool="lcov-parser",
            parsed_value={"total_pct": total_pct, "line_pct": total_pct},
        ),
    )


def _finding(dimension: str, severity: str) -> Finding:
    """A simple heuristic finding at a given dimension/severity.

    evidence_type='heuristic' (not 'static') so the SAFE-01 critical-static
    caveat requirement does not apply; confidence='high' so the SCH-04
    candidate rung-cap (forbids critical/blocker at candidate) does not apply.
    """
    return Finding(
        dimension=dimension,
        severity=severity,
        evidence_type="heuristic",
        confidence="high",
        source_tool="tsc",
        rule_id="TSXXXX",
        evidence=Evidence(tool="tsc"),
    )


def _scan_report(*, findings: list[Finding], **meta_overrides) -> ScanReport:
    base = dict(
        repo_slug="example-app",
        commit_sha="a" * 40,
        scan_date=date(2026, 5, 20),
        tool_version="0.1.0",
    )
    base.update(meta_overrides)
    return ScanReport(meta=ReportMeta(**base), findings=findings)


def _write_sidecar(repo_path: Path, report: ScanReport) -> Path:
    """Write the JSON sidecar AND a sibling .md (with garbage numbers)."""
    out_dir = repo_path / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"example-app-state-report-{report.meta.scan_date.isoformat()}"
    json_path = out_dir / f"{stem}.json"
    md_path = out_dir / f"{stem}.md"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")
    # DELIBERATELY DIFFERENT numbers in the markdown — the aggregator must
    # ignore these entirely.
    md_path.write_text(
        "# State Report\n\nBlockers: 999\nCritical: 888\nCoverage: 11.1%\n",
        encoding="utf-8",
    )
    return json_path


def test_reads_json_not_md(tmp_path):
    """SC-6 / FLEET-02: aggregation reads the JSON sidecar ONLY.

    The .md carries garbage counts; the snapshot must match the JSON. Mutating
    the .md afterward must not change a re-aggregated snapshot.
    """
    repo = tmp_path / "example-app"
    repo.mkdir()
    report = _scan_report(
        findings=[
            _finding("security", "blocker"),
            _finding("security", "critical"),
            _finding("correctness", "major"),
            _coverage_finding(73.4),
        ],
    )
    json_path = _write_sidecar(repo, report)
    md_path = json_path.with_suffix(".md")

    row1 = build_repo_row(repo, json_path)
    snap1 = aggregate([row1], sweep_root=tmp_path, generated_date=date(2026, 5, 29))

    # Counts come from the JSON, NOT the .md's 999/888/11.1.
    assert snap1.total_blockers == 1
    assert snap1.total_critical == 1
    assert row1.severity_by_dimension["security"] == {"blocker": 1, "critical": 1}
    assert row1.severity_by_dimension["correctness"] == {"major": 1}
    assert row1.coverage_pct == 73.4
    assert row1.status == "ok"

    # Now MUTATE the markdown to even more absurd values and re-aggregate.
    md_path.write_text(
        "# Tampered\n\nBlockers: -1\nCritical: 100000\nCoverage: 0.0%\n",
        encoding="utf-8",
    )
    row2 = build_repo_row(repo, json_path)
    snap2 = aggregate([row2], sweep_root=tmp_path, generated_date=date(2026, 5, 29))

    assert snap2.total_blockers == snap1.total_blockers == 1
    assert snap2.total_critical == snap1.total_critical == 1
    assert row2.coverage_pct == row1.coverage_pct == 73.4
    assert row2.severity_by_dimension == row1.severity_by_dimension


def test_failed_sidecar_yields_failed_row(tmp_path):
    """Corrupt sidecar -> status='failed' row with error_reason, no crash (T-05-05)."""
    repo = tmp_path / "brokenrepo"
    repo.mkdir()
    bad = repo / "sidecar.json"
    bad.write_text("{not valid json at all", encoding="utf-8")

    row = build_repo_row(repo, bad)

    assert row.status == "failed"
    assert row.error_reason is not None
    assert row.repo_slug == "brokenrepo"  # falls back to dir name
    assert row.coverage_pct is None
    assert row.severity_by_dimension == {}

    snap = aggregate([row], sweep_root=tmp_path, generated_date=date(2026, 5, 29))
    assert snap.failed_count == 1
    assert snap.total_repos == 1
    assert snap.total_blockers == 0


def test_missing_sidecar_file_yields_failed_row(tmp_path):
    """A sidecar path that does not exist -> failed row (OSError tolerated)."""
    repo = tmp_path / "gone"
    repo.mkdir()
    row = build_repo_row(repo, repo / "nope.json")
    assert row.status == "failed"
    assert row.error_reason is not None


def test_make_failed_row_for_crashed_scan(tmp_path):
    """make_failed_row builds a failed row for a scan that crashed pre-sidecar."""
    repo = tmp_path / "crashed"
    repo.mkdir()
    row = make_failed_row(repo, error_reason="scan raised RuntimeError: boom")
    assert row.status == "failed"
    assert row.repo_slug == "crashed"
    assert "boom" in row.error_reason


def test_none_meta_fields_no_agent(tmp_path):
    """RESEARCH Pitfall 5: --no-agent sidecar (cost/seconds None, commit UNCOMMITTED)
    aggregates without crashing; cost/seconds carried as None (not 0)."""
    repo = tmp_path / "fresh"
    repo.mkdir()
    report = _scan_report(
        findings=[_finding("quality", "major")],
        commit_sha="UNCOMMITTED",
        agent_status=None,
        total_cost_usd=None,
        token_usage=None,
        wall_clock_seconds=None,
    )
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    json_path = out_dir / "fresh-state-report-2026-05-20.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    row = build_repo_row(repo, json_path)

    assert row.status == "ok"
    assert row.commit_sha == "UNCOMMITTED"
    assert row.scan_cost_usd is None
    assert row.scan_seconds is None
    # No coverage finding present -> None, NOT 0.0 (SAFE-04).
    assert row.coverage_pct is None

    snap = aggregate(
        [row], sweep_root=tmp_path, generated_date=date(2026, 5, 29),
        total_cost_usd=None, sweep_seconds=None,
    )
    assert snap.total_cost_usd is None
    assert snap.sweep_seconds is None
    assert snap.failed_count == 0


def test_unavailable_coverage_is_none_not_zero(tmp_path):
    """An lcov coverage finding without total_pct (unavailable) -> coverage_pct None."""
    repo = tmp_path / "nocov"
    repo.mkdir()
    unavailable_cov = Finding(
        dimension="test_integrity",
        severity="info",
        evidence_type="unavailable",
        confidence="high",
        source_tool="lcov",
        rule_id="coverage_summary",
        evidence=Evidence(tool="lcov-parser", parsed_value={"reason": "stale_or_missing"}),
    )
    report = _scan_report(findings=[unavailable_cov], repo_slug="nocov")
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    json_path = out_dir / "nocov.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    row = build_repo_row(repo, json_path)
    assert row.coverage_pct is None


def test_last_commit_iso_from_real_repo(fake_repo):
    """last_commit_iso is populated from a real pygit2 repo; None on no-commit dir."""
    repo = fake_repo({"package.json": "{}"}, name="committed")
    report = _scan_report(findings=[], repo_slug="committed")
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    json_path = out_dir / "committed.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    row = build_repo_row(repo, json_path)
    assert row.last_commit_iso is not None
    assert row.last_commit_iso.startswith("2026-05-28")  # fixture's seeded ts


def test_minor_info_excluded_from_counts(tmp_path):
    """Only blocker/critical/major are counted per dimension; minor/info ignored."""
    repo = tmp_path / "mix"
    repo.mkdir()
    report = _scan_report(
        findings=[
            _finding("security", "blocker"),
            _finding("security", "minor"),
            _finding("quality", "info"),
            _finding("quality", "major"),
        ],
        repo_slug="mix",
    )
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    json_path = out_dir / "mix.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    row = build_repo_row(repo, json_path)
    assert row.severity_by_dimension["security"] == {"blocker": 1}
    assert row.severity_by_dimension["quality"] == {"major": 1}


def test_aggregate_sums_across_ok_rows_only(tmp_path):
    """Fleet totals sum ok rows; failed rows contribute nothing but failed_count."""
    ok_row = FleetRepoRow(
        repo_slug="a", repo_path="/x/a", status="ok",
        severity_by_dimension={"security": {"blocker": 2, "critical": 1}},
    )
    ok_row2 = FleetRepoRow(
        repo_slug="b", repo_path="/x/b", status="ok",
        severity_by_dimension={"correctness": {"critical": 3}},
    )
    failed = FleetRepoRow(
        repo_slug="c", repo_path="/x/c", status="failed", error_reason="boom",
    )
    snap = aggregate(
        [ok_row, ok_row2, failed],
        sweep_root="/x", generated_date=date(2026, 5, 29),
        total_cost_usd=1.5, sweep_seconds=42.0,
    )
    assert snap.total_repos == 3
    assert snap.total_blockers == 2
    assert snap.total_critical == 4
    assert snap.failed_count == 1
    assert snap.total_cost_usd == 1.5
    assert snap.sweep_seconds == 42.0
