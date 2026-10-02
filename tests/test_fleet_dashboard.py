"""Tests for the fleet dashboard renderer (Plan 05-05 / FLEET-03 / SC-4).

Coverage:
- rollup header line present with correct totals (D-05-11)
- failed rows pinned ABOVE worst-health ok rows (D-05-10), ok rows ranked
  worst-health-first (D-05-08)
- one table row per repo
- coverage None renders "n/a" (SAFE-04)
- a planted secret in a row field triggers the lint refusal: render returns 2
  and NO file is written (T-05-08 / D-06).
"""
from __future__ import annotations

from datetime import date

from repo_audit.fleet.dashboard import render_fleet_dashboard
from repo_audit.schema.fleet import FleetRepoRow, FleetSnapshot


def _ok_row(slug, *, blockers=0, critical=0, major=0, coverage=None):
    sev: dict[str, dict[str, int]] = {}
    if blockers:
        sev.setdefault("security", {})["blocker"] = blockers
    if critical:
        sev.setdefault("security", {})["critical"] = critical
    if major:
        sev.setdefault("test_integrity", {})["major"] = major
    return FleetRepoRow(
        repo_slug=slug,
        repo_path=f"/code/{slug}",
        status="ok",
        commit_sha="a" * 40,
        last_commit_iso="2026-05-20T10:00:00+00:00",
        scan_date=date(2026, 5, 29),
        severity_by_dimension=sev,
        coverage_pct=coverage,
        scan_cost_usd=None,
        scan_seconds=None,
    )


def _failed_row(slug, reason):
    return FleetRepoRow(
        repo_slug=slug,
        repo_path=f"/code/{slug}",
        status="failed",
        error_reason=reason,
    )


def _snapshot(rows):
    blockers = sum(
        sev.get("blocker", 0)
        for r in rows
        if r.status == "ok"
        for sev in r.severity_by_dimension.values()
    )
    critical = sum(
        sev.get("critical", 0)
        for r in rows
        if r.status == "ok"
        for sev in r.severity_by_dimension.values()
    )
    failed = sum(1 for r in rows if r.status == "failed")
    return FleetSnapshot(
        generated_date=date(2026, 5, 29),
        sweep_root="/code",
        total_repos=len(rows),
        total_blockers=blockers,
        total_critical=critical,
        failed_count=failed,
        total_cost_usd=None,
        sweep_seconds=12.3,
        repos=rows,
    )


def test_rollup_header_and_rows(tmp_path):
    rows = [
        _ok_row("low", major=1, coverage=88.5),
        _ok_row("worst", blockers=3, critical=2),
        _failed_row("broken", "RuntimeError: boom"),
    ]
    snap = _snapshot(rows)
    md_path = tmp_path / "fleet-dashboard-2026-05-29.md"

    rc = render_fleet_dashboard(snap, md_path)
    assert rc == 0
    dash = md_path.read_text(encoding="utf-8")

    # (a) rollup header with correct totals (D-05-11).
    assert "3 repos scanned · 3 blockers, 2 critical across fleet · 1 failed" in dash
    assert "swept in 12.3s" in dash
    assert "total cost n/a" in dash  # None cost -> n/a, not $0.

    # (c) one row per repo (3 data rows in the table body).
    body_rows = [
        ln for ln in dash.splitlines()
        if ln.startswith("| `")
    ]
    assert len(body_rows) == 3

    # (b) failed row pinned ABOVE worst-health ok row, which is above the
    # low-health ok row.
    order = [ln for ln in dash.splitlines() if ln.startswith("| `")]
    assert order[0].startswith("| `broken`")   # failed first (D-05-10)
    assert order[1].startswith("| `worst`")     # worst-health ok next (D-05-08)
    assert order[2].startswith("| `low`")

    # (d) coverage None renders n/a; the covered repo shows its pct.
    assert "88.5%" in dash
    assert "| n/a |" in dash  # the worst/broken rows have None coverage

    # failed row carries its error reason.
    assert "RuntimeError: boom" in dash


def test_json_sidecar_written_alongside(tmp_path):
    snap = _snapshot([_ok_row("a", coverage=50.0)])
    md_path = tmp_path / "fleet-dashboard-2026-05-29.md"
    rc = render_fleet_dashboard(snap, md_path)
    assert rc == 0
    json_path = tmp_path / "fleet-2026-05-29.json"
    assert json_path.exists()
    # The JSON preserves canonical discovery order, not the re-ranked view.
    text = json_path.read_text(encoding="utf-8")
    assert '"schema_version": "1"' in text
    assert '"repo_slug": "a"' in text


def test_planted_secret_refuses_no_write(tmp_path):
    """T-05-08 / D-06: a secret in a row field triggers secret-lint refusal —
    render returns 2 and NO file is written."""
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"  # canonical AWS example key
    rows = [_failed_row("leaky", f"auth failed using {aws_key}")]
    snap = _snapshot(rows)
    md_path = tmp_path / "fleet-dashboard-2026-05-29.md"

    rc = render_fleet_dashboard(snap, md_path)

    assert rc == 2
    assert not md_path.exists()
    assert not (tmp_path / "fleet-2026-05-29.json").exists()


def test_random_looking_sweep_root_is_not_a_secret(tmp_path):
    """The sweep root is the operator's own directory, which repo-audit prints
    itself. A path with a session UUID in it used to trip the entropy backstop
    on the ``_Sweep root:`` line and refuse the whole dashboard."""
    root = "/tmp/runs/3f9c2a71-58d4-4e0b-9b6a-c41e7d02a8f5/workspace/fleet"
    row = _ok_row("adapt-website", major=2)
    row = row.model_copy(update={"repo_path": f"{root}/adapt-website"})
    snap = _snapshot([row]).model_copy(update={"sweep_root": root})
    md_path = tmp_path / "fleet-dashboard-2026-05-29.md"

    rc = render_fleet_dashboard(snap, md_path)

    assert rc == 0
    assert root in md_path.read_text(encoding="utf-8")


def test_secret_beside_the_sweep_root_still_refuses(tmp_path):
    """Masking the sweep root does not mask anything else in the buffer."""
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    root = "/tmp/3f9c2a71-58d4-4e0b-9b6a-c41e7d02a8f5/fleet"
    snap = _snapshot([_failed_row("leaky", f"auth failed using {aws_key}")])
    snap = snap.model_copy(update={"sweep_root": root})
    md_path = tmp_path / "fleet-dashboard-2026-05-29.md"

    rc = render_fleet_dashboard(snap, md_path)

    assert rc == 2
    assert not md_path.exists()
