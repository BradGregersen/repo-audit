"""Plan 05-01 Task 2 — find_prior_sidecar() TREND-01 most-recent-prior selection.

Covers the five behaviors from the plan's <behavior> block:
  1. Two sidecars (yesterday + day-before), today's run → returns yesterday's.
  2. Only today's sidecars exist (same-day re-run, Pitfall 3) → returns None.
  3. No docs/state-reports dir or no JSON sidecars → returns None.
  4. Corrupt/unparseable prior JSON → skipped gracefully, does not crash
     (T-05-01: ValidationError / JSONDecodeError → no usable baseline).
  5. run_scan sets baseline_run=False when a prior exists, True when None.

The authoritative date is meta.scan_date inside the payload (NOT the filename).
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from repo_audit.meta.paths import find_prior_sidecar
from repo_audit.orchestration import run_scan
from repo_audit.schema.report import ReportMeta, ScanReport

TODAY = date(2026, 5, 29)
YESTERDAY = TODAY - timedelta(days=1)
DAY_BEFORE = TODAY - timedelta(days=2)


def _write_sidecar(repo: Path, scan_date: date, *, slug: str = "x", name: str | None = None) -> Path:
    """Write a valid ScanReport JSON sidecar dated scan_date; return its path."""
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    report = ScanReport(
        meta=ReportMeta(
            repo_slug=slug,
            commit_sha="DEADBEEF",
            scan_date=scan_date,
            tool_version="0.0.0",
        ),
    )
    fname = name or f"{slug}-state-report-{scan_date.isoformat()}.json"
    path = out_dir / fname
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


# --- Behavior 1: most-recent prior before today ---


def test_returns_most_recent_prior_before_today(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="prior-recent")
    _write_sidecar(repo, DAY_BEFORE)
    expected = _write_sidecar(repo, YESTERDAY)
    result = find_prior_sidecar(repo, TODAY)
    assert result == expected


def test_uses_payload_date_not_filename(fake_repo):
    """meta.scan_date is authoritative; a misleading filename does not win."""
    repo = fake_repo({"README.md": "# x\n"}, name="prior-payload")
    # Filename claims today, payload says day-before → still a valid prior.
    _write_sidecar(repo, DAY_BEFORE, name="x-state-report-2026-05-29.json")
    # Filename claims old, payload says yesterday → this is the real most-recent.
    expected = _write_sidecar(repo, YESTERDAY, name="x-state-report-2000-01-01.json")
    result = find_prior_sidecar(repo, TODAY)
    assert result == expected


# --- Behavior 2: only today's sidecars → None (Pitfall 3, same-day re-run) ---


def test_only_today_sidecars_returns_none(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="prior-today-only")
    _write_sidecar(repo, TODAY)
    assert find_prior_sidecar(repo, TODAY) is None


# --- Behavior 3: no dir / no JSON → None ---


def test_no_state_reports_dir_returns_none(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="prior-nodir")
    assert not (repo / "docs" / "state-reports").exists()
    assert find_prior_sidecar(repo, TODAY) is None


def test_no_json_sidecars_returns_none(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="prior-nojson")
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    # Only a markdown report, no JSON.
    (out_dir / "x-state-report-2026-05-28.md").write_text("# r", encoding="utf-8")
    assert find_prior_sidecar(repo, TODAY) is None


# --- Behavior 4: corrupt JSON skipped gracefully (T-05-01) ---


def test_corrupt_json_is_skipped_not_crashed(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="prior-corrupt")
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    # Not valid JSON at all.
    (out_dir / "broken-state-report-2026-05-28.json").write_text("{not json", encoding="utf-8")
    # Valid JSON but fails schema (extra='forbid' / missing required fields).
    (out_dir / "bad-schema-state-report-2026-05-27.json").write_text(
        '{"totally": "wrong"}', encoding="utf-8"
    )
    # Does not raise; no usable baseline among the two corrupt files.
    assert find_prior_sidecar(repo, TODAY) is None


def test_corrupt_json_alongside_valid_prior_returns_valid(fake_repo):
    """A corrupt sidecar must not hide a valid prior."""
    repo = fake_repo({"README.md": "# x\n"}, name="prior-mixed")
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    (out_dir / "broken-state-report-2026-05-28.json").write_text("not json", encoding="utf-8")
    expected = _write_sidecar(repo, YESTERDAY)
    assert find_prior_sidecar(repo, TODAY) == expected


# --- Behavior 5: run_scan baseline_run reflects prior existence ---


def test_run_scan_baseline_true_when_no_prior(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="baseline-true")
    result = run_scan(repo, no_agent=True)
    assert result.scan_report.meta.baseline_run is True
    assert result.prior_sidecar is None


def test_run_scan_baseline_false_when_prior_exists(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="baseline-false")
    # Seed a yesterday-dated prior sidecar (slug must match the repo name so it
    # is a plausible prior, though find_prior_sidecar keys on scan_date not slug).
    _write_sidecar(repo, date.today() - timedelta(days=1), slug="baseline-false")
    result = run_scan(repo, no_agent=True)
    assert result.scan_report.meta.baseline_run is False
    assert result.prior_sidecar is not None
