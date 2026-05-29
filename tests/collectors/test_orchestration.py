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

Plan 03-05 extensions (appended; do not alter existing Phase 2 tests):
    4. build_scope_ledger accepts ``adapter_results`` kwarg-only param (default None).
       - Backward compatibility: calling without it still works.
       - Scanned: AdapterResult source_adapter/source_tool names sorted-union
         with CollectorResult source_collector names into ScannedEntry.collectors.
       - Unavailable: each non-ok AdapterResult adds one UnavailableEntry with
         dimension=adapter.dimension, collector='source_adapter:source_tool',
         reason=adapter.notes or adapter.status.
"""
from datetime import date
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
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


# ---------------------------------------------------------------------------
# Plan 03-05 Task 1 extensions: adapter_results folding into ScopeLedger.
# Each test constructs synthetic walker + collector + adapter inputs so the
# folding logic can be exercised without standing up a full TS toolchain.
# ---------------------------------------------------------------------------


def _walker_with_one_dir(tmp_path):
    """Build a minimal WalkerResult-shaped object for ledger tests.

    Includes a ``src/`` subdir so walker.scanned_dirs is non-empty (the
    walker logs top-level subdirs, not the repo root itself).
    """
    repo = tmp_path / "ledger-adapter-target"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()
    (src / "main.py").write_text("x=1\n", encoding="utf-8")
    return build_repo_index(repo), repo


def test_build_scope_ledger_without_adapter_results_kwarg(tmp_path):
    """Backward compat: existing Phase 2 callsite shape still builds the ledger."""
    wr, repo = _walker_with_one_dir(tmp_path)
    results = [
        CollectorResult(
            status="ok",
            source_collector="git_cadence",
            dimension="process",
        ),
    ]
    sl = build_scope_ledger(wr, results, repo_path=repo)
    # Ledger built; no adapter_results passed → no adapter rows.
    assert len(sl.scanned) >= 1
    assert sl.unavailable == []
    # Scanned collectors list should contain ONLY the collector name.
    assert sl.scanned[0].collectors == ["git_cadence"]


def test_build_scope_ledger_adapter_results_extends_scanned_collectors(tmp_path):
    """Adapter labels sort-union into ScannedEntry.collectors alongside collectors."""
    wr, repo = _walker_with_one_dir(tmp_path)
    collectors = [
        CollectorResult(
            status="ok",
            source_collector="git_cadence",
            dimension="process",
        ),
    ]
    adapters = [
        AdapterResult(
            status="ok",
            source_adapter="typescript-node",
            source_tool="tsc",
            dimension="correctness",
        ),
    ]
    sl = build_scope_ledger(
        wr, collectors, repo_path=repo, adapter_results=adapters,
    )
    # Expected: sorted union = ['git_cadence', 'typescript-node:tsc']
    assert sl.scanned[0].collectors == ["git_cadence", "typescript-node:tsc"]


def test_build_scope_ledger_adapter_unavailable_creates_entry(tmp_path):
    """Each non-ok AdapterResult contributes one UnavailableEntry."""
    wr, repo = _walker_with_one_dir(tmp_path)
    adapters = [
        AdapterResult(
            status="unavailable",
            notes="tsc not found in PATH",
            source_adapter="typescript-node",
            source_tool="tsc",
            dimension="correctness",
        ),
    ]
    sl = build_scope_ledger(
        wr, [], repo_path=repo, adapter_results=adapters,
    )
    assert len(sl.unavailable) == 1
    entry = sl.unavailable[0]
    assert entry.dimension == "correctness"
    assert entry.collector == "typescript-node:tsc"
    assert entry.reason == "tsc not found in PATH"


def test_build_scope_ledger_adapter_timeout_creates_entry(tmp_path):
    """status='timeout' is also non-ok → UnavailableEntry."""
    wr, repo = _walker_with_one_dir(tmp_path)
    adapters = [
        AdapterResult(
            status="timeout",
            notes="timeout after 120.0s",
            source_adapter="typescript-node",
            source_tool="eslint",
            dimension="quality_debt",
        ),
    ]
    sl = build_scope_ledger(
        wr, [], repo_path=repo, adapter_results=adapters,
    )
    assert len(sl.unavailable) == 1
    entry = sl.unavailable[0]
    assert entry.dimension == "quality_debt"
    assert entry.collector == "typescript-node:eslint"
    assert entry.reason == "timeout after 120.0s"


def test_build_scope_ledger_adapter_ok_does_not_create_unavailable(tmp_path):
    """status='ok' adapter does NOT contribute to Unavailable subsection."""
    wr, repo = _walker_with_one_dir(tmp_path)
    adapters = [
        AdapterResult(
            status="ok",
            source_adapter="typescript-node",
            source_tool="tsc",
            dimension="correctness",
        ),
    ]
    sl = build_scope_ledger(
        wr, [], repo_path=repo, adapter_results=adapters,
    )
    assert sl.unavailable == []


def test_build_scope_ledger_handles_missing_adapter_fields(tmp_path):
    """Defensive: AdapterResult with empty source_adapter/source_tool ⇒ 'adapter:unknown'."""
    wr, repo = _walker_with_one_dir(tmp_path)
    adapters = [
        AdapterResult(
            status="unavailable",
            notes="catastrophic dispatch failure",
            # Intentionally empty:
            source_adapter="",
            source_tool="",
            dimension="",
        ),
    ]
    sl = build_scope_ledger(
        wr, [], repo_path=repo, adapter_results=adapters,
    )
    assert len(sl.unavailable) == 1
    entry = sl.unavailable[0]
    assert entry.collector == "adapter:unknown"
    assert entry.dimension == "unknown"
    assert entry.reason == "catastrophic dispatch failure"


def test_build_scope_ledger_mixed_adapter_statuses(tmp_path):
    """Mixed statuses: ok+timeout+unavailable+ok → 2 Unavailable rows; all 4 in Scanned."""
    wr, repo = _walker_with_one_dir(tmp_path)
    adapters = [
        AdapterResult(
            status="ok", source_adapter="typescript-node", source_tool="tsc",
            dimension="correctness",
        ),
        AdapterResult(
            status="timeout", source_adapter="typescript-node", source_tool="eslint",
            dimension="quality_debt", notes="timeout after 90.0s",
        ),
        AdapterResult(
            status="unavailable", source_adapter="typescript-node", source_tool="knip",
            dimension="architecture_rot", notes="knip not on PATH",
        ),
        AdapterResult(
            status="ok", source_adapter="typescript-node", source_tool="coverage_lcov",
            dimension="test_integrity",
        ),
    ]
    sl = build_scope_ledger(
        wr, [], repo_path=repo, adapter_results=adapters,
    )
    # All 4 adapter labels in Scanned.collectors (sorted).
    assert sl.scanned[0].collectors == sorted([
        "typescript-node:tsc", "typescript-node:eslint",
        "typescript-node:knip", "typescript-node:coverage_lcov",
    ])
    # 2 Unavailable rows (timeout + unavailable).
    assert len(sl.unavailable) == 2
    collectors_unavail = {u.collector for u in sl.unavailable}
    assert collectors_unavail == {"typescript-node:eslint", "typescript-node:knip"}
