"""Orchestration layer tests: build_scope_ledger + render_and_write completion-honesty wiring.

These tests pin Plan 02-06 Task 1's contracts:
    1. build_scope_ledger assembles ScopeLedger from WalkerResult + list[CollectorResult]
       - Scanned: one entry per walker_result.scanned_dirs
       - Skipped: one entry per walker_result.skipped_dirs (auto-logged in walker)
       - Unavailable: one entry per non-ok CollectorResult
    2. render_and_write extends with completion_honesty_lint between secret-lint
       and _write_outputs, raising exit code 3 on partial-scan overclaim.
    3. A clean partial scan (no forbidden tokens in any rendered prose) returns 0
       and writes both files -- proving the partial banner itself does not trip
       the chokepoint (Pitfall 5 mitigation regression gate).
"""
from datetime import date
from pathlib import Path

from repo_audit.collectors.base import CollectorResult
from repo_audit.orchestration import build_scope_ledger
from repo_audit.schema import ReportMeta, ScanReport, ScopeLedger
from repo_audit.walker import build_repo_index


def test_build_scope_ledger_populates_scanned_skipped_unavailable(tmp_path):
    """SC-2 / REP-04 — three subsections written from walker + collector returns."""
    repo = tmp_path / "ledger-target"
    repo.mkdir()
    (repo / "src.py").write_text("x=1\n", encoding="utf-8")
    nm = repo / "node_modules"
    nm.mkdir()
    (nm / "junk.js").write_text("//\n", encoding="utf-8")
    wr = build_repo_index(repo)
    results = [
        CollectorResult(
            status="ok",
            source_collector="loc_inventory",
            dimension="quality",
        ),
        CollectorResult(
            status="partial",
            source_collector="secret_detection",
            dimension="security",
            notes="gitleaks not on PATH",
        ),
        CollectorResult(
            status="unavailable",
            source_collector="git_cadence",
            dimension="process",
            notes="no commits",
        ),
    ]
    sl = build_scope_ledger(wr, results, repo_path=repo)
    # Skipped: node_modules logged with reason='dependencies'
    assert any(s.reason == "dependencies" for s in sl.skipped)
    # Unavailable: 2 entries (partial + unavailable)
    assert len(sl.unavailable) == 2
    dims = {u.dimension for u in sl.unavailable}
    assert dims == {"security", "process"}


def test_render_and_write_completion_honesty_exit_3_on_partial_violation(tmp_path):
    """D-32 / SAFE-08 — partial scan with forbidden token in rendered prose returns 3.

    Crafted by injecting the forbidden token via scope_ledger.notes (which IS
    rendered as `> {{ notes }}`). meta.partial=True triggers the chokepoint.
    """
    from repo_audit.render.renderer import render_and_write
    md = tmp_path / "r.md"
    js = tmp_path / "r.json"
    meta = ReportMeta(
        repo_slug="violator",
        commit_sha="0" * 40,
        scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
        partial=True,
    )
    sl = ScopeLedger(
        notes="All collectors ran successfully and every dimension is complete.",
    )
    sr = ScanReport(
        schema_version="1", meta=meta, findings=[], scope_ledger=sl,
    )
    rc = render_and_write(sr, md, js)
    assert rc == 3
    # No files written
    assert not md.exists()
    assert not js.exists()


def test_render_and_write_zero_on_clean_partial_scan(tmp_path):
    """Partial scan with no forbidden tokens in any rendered prose → returns 0, writes both files."""
    from repo_audit.render.renderer import render_and_write
    md = tmp_path / "ok.md"
    js = tmp_path / "ok.json"
    meta = ReportMeta(
        repo_slug="clean",
        commit_sha="0" * 40,
        scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
        partial=True,
    )
    sr = ScanReport(
        schema_version="1",
        meta=meta,
        findings=[],
        scope_ledger=ScopeLedger(),
    )
    rc = render_and_write(sr, md, js)
    assert rc == 0
    assert md.exists()
    assert js.exists()
    body = md.read_text()
    assert "Partial scan" in body
