"""Tests for the fleet sweep + ``repo-audit fleet`` CLI command (Plan 05-05).

Coverage:
- ``test_failure_does_not_abort`` (FLEET-04 / SC-5 / T-05-10): one repo whose
  scan RAISES becomes a ``status='failed'`` row and the sweep continues — the
  other repos still produce ``status='ok'`` rows. Nothing aborts the sweep.
- ``test_rc_nonzero_is_failed_row``: a scan that completes but whose render was
  refused (``rc != 0``) is a failed row, not a raise.
- ``test_zero_repos_returns_empty_snapshot``: a sweep root with no ``.git``
  children yields an empty snapshot (no invented rows).
- CLI end-to-end (``test_fleet_e2e`` / ``test_fleet_continues_past_failure``):
  the wired ``repo-audit fleet`` command writes the gitignored reports/ pair, lists
  every repo, and survives a per-repo failure (deterministic / offline).
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pygit2
import pytest
from typer.testing import CliRunner

from repo_audit.fleet import sweep as sweep_mod
from repo_audit.fleet.sweep import run_fleet
from repo_audit.orchestration.scan_runner import ScanResult
from repo_audit.schema.report import ReportMeta, ScanReport


def _make_repo(parent: Path, name: str) -> Path:
    """Create an initialized git repo dir with one commit under ``parent``."""
    repo_path = parent / name
    repo_path.mkdir(parents=True)
    repo = pygit2.init_repository(str(repo_path), bare=False)
    (repo_path / "README.md").write_text(f"# {name}\n", encoding="utf-8")
    repo.index.add("README.md")
    repo.index.write()
    sig = pygit2.Signature("Tester", "tester@example.com")
    tree = repo.index.write_tree()
    repo.create_commit("HEAD", sig, sig, "initial", tree, [])
    return repo_path


def _write_sidecar(repo_path: Path, slug: str) -> Path:
    """Write a minimal valid JSON sidecar in the repo's docs/state-reports/."""
    out_dir = repo_path / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    report = ScanReport(
        meta=ReportMeta(
            repo_slug=slug,
            commit_sha="a" * 40,
            scan_date=date(2026, 5, 29),
            tool_version="0.1.0",
        ),
        findings=[],
    )
    json_path = out_dir / f"{slug}-state-report-2026-05-29.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")
    return json_path


def test_failure_does_not_abort(tmp_path, monkeypatch):
    """FLEET-04 / SC-5: a per-repo scan exception becomes a failed row; the
    sweep continues and the other repos still produce ok rows."""
    fleet_root = tmp_path / "fleet"
    fleet_root.mkdir()
    _make_repo(fleet_root, "alpha")
    boom = _make_repo(fleet_root, "boom")
    _make_repo(fleet_root, "zeta")

    def fake_run_scan(repo_path, *, no_agent=False, **kwargs):
        repo_path = Path(repo_path)
        if repo_path.name == "boom":
            raise RuntimeError("collector exploded")
        slug = repo_path.name
        json_path = _write_sidecar(repo_path, slug)
        return ScanResult(
            scan_report=ScanReport(
                meta=ReportMeta(
                    repo_slug=slug,
                    commit_sha="a" * 40,
                    scan_date=date(2026, 5, 29),
                    tool_version="0.1.0",
                ),
                findings=[],
            ),
            md_path=json_path.with_suffix(".md"),
            json_path=json_path,
            rc=0,
            agent_status=None,
        )

    monkeypatch.setattr(sweep_mod, "run_scan", fake_run_scan)

    snapshot = run_fleet(fleet_root)

    assert snapshot.total_repos == 3
    by_status = {r.repo_slug: r.status for r in snapshot.repos}
    assert by_status == {"alpha": "ok", "boom": "failed", "zeta": "ok"}
    failed = next(r for r in snapshot.repos if r.status == "failed")
    assert "RuntimeError" in failed.error_reason
    assert "collector exploded" in failed.error_reason
    assert snapshot.failed_count == 1


def test_rc_nonzero_is_failed_row(tmp_path, monkeypatch):
    """A completed scan whose render was refused (rc != 0) is a failed row,
    not a raise — the sweep continues."""
    fleet_root = tmp_path / "fleet"
    fleet_root.mkdir()
    _make_repo(fleet_root, "leaky")

    def fake_run_scan(repo_path, *, no_agent=False, **kwargs):
        repo_path = Path(repo_path)
        return ScanResult(
            scan_report=ScanReport(
                meta=ReportMeta(
                    repo_slug=repo_path.name,
                    commit_sha="a" * 40,
                    scan_date=date(2026, 5, 29),
                    tool_version="0.1.0",
                ),
                findings=[],
            ),
            md_path=repo_path / "x.md",
            json_path=repo_path / "x.json",
            rc=2,  # secret-lint refused
            agent_status=None,
        )

    monkeypatch.setattr(sweep_mod, "run_scan", fake_run_scan)

    snapshot = run_fleet(fleet_root)
    assert snapshot.total_repos == 1
    row = snapshot.repos[0]
    assert row.status == "failed"
    assert "rc=2" in row.error_reason


def test_zero_repos_returns_empty_snapshot(tmp_path):
    """A sweep root with no .git children yields an empty snapshot — no
    invented rows."""
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "not_a_repo").mkdir()
    snapshot = run_fleet(empty)
    assert snapshot.total_repos == 0
    assert snapshot.repos == []
    assert snapshot.failed_count == 0


# --------------------------------------------------------------------------- #
# CLI end-to-end (added in Task 3).
# --------------------------------------------------------------------------- #

runner = CliRunner()


def _fake_scan_writes_sidecar(repo_path, *, no_agent=False, **kwargs):
    repo_path = Path(repo_path)
    slug = repo_path.name
    json_path = _write_sidecar(repo_path, slug)
    return ScanResult(
        scan_report=ScanReport(
            meta=ReportMeta(
                repo_slug=slug,
                commit_sha="a" * 40,
                scan_date=date(2026, 5, 29),
                tool_version="0.1.0",
            ),
            findings=[],
        ),
        md_path=json_path.with_suffix(".md"),
        json_path=json_path,
        rc=0,
        agent_status=None,
    )


def test_fleet_e2e(tmp_path, monkeypatch):
    """CLI-03 / FLEET-03 / SC-4: repo-audit fleet sweeps a dir, exits 0, both repos
    appear, fleet JSON + dashboard md are written to reports/."""
    from repo_audit import cli as cli_mod

    fleet_root = tmp_path / "fleet"
    fleet_root.mkdir()
    _make_repo(fleet_root, "alpha")
    _make_repo(fleet_root, "beta")

    monkeypatch.setattr(sweep_mod, "run_scan", _fake_scan_writes_sidecar)

    reports_dir = tmp_path / "reports"
    json_path = reports_dir / "fleet-2026-05-29.json"
    md_path = reports_dir / "fleet-dashboard-2026-05-29.md"

    def fake_fleet_paths(root, gen_date):
        return json_path, md_path

    monkeypatch.setattr(cli_mod, "fleet_report_paths", fake_fleet_paths)

    result = runner.invoke(cli_mod.app, ["fleet", str(fleet_root)])

    assert result.exit_code == 0, result.output
    assert json_path.exists()
    assert md_path.exists()
    dash = md_path.read_text(encoding="utf-8")
    assert "alpha" in dash
    assert "beta" in dash
    assert "2 repos scanned" in dash


def test_fleet_continues_past_failure(tmp_path, monkeypatch):
    """FLEET-04 via the CLI: a failing repo becomes a row, exit stays 0."""
    from repo_audit import cli as cli_mod

    fleet_root = tmp_path / "fleet"
    fleet_root.mkdir()
    _make_repo(fleet_root, "good")
    _make_repo(fleet_root, "bad")

    def fake_run_scan(repo_path, *, no_agent=False, **kwargs):
        if Path(repo_path).name == "bad":
            raise RuntimeError("kaboom")
        return _fake_scan_writes_sidecar(repo_path, no_agent=no_agent)

    monkeypatch.setattr(sweep_mod, "run_scan", fake_run_scan)

    reports_dir = tmp_path / "reports"
    json_path = reports_dir / "fleet-2026-05-29.json"
    md_path = reports_dir / "fleet-dashboard-2026-05-29.md"
    monkeypatch.setattr(
        cli_mod, "fleet_report_paths", lambda root, gen_date: (json_path, md_path)
    )

    result = runner.invoke(cli_mod.app, ["fleet", str(fleet_root)])

    assert result.exit_code == 0, result.output
    dash = md_path.read_text(encoding="utf-8")
    assert "good" in dash
    assert "bad" in dash
    assert "kaboom" in dash


def test_fleet_zero_repos_cli(tmp_path):
    """A sweep dir with no repos echoes an honest message and exits 0."""
    from repo_audit import cli as cli_mod

    empty = tmp_path / "empty"
    empty.mkdir()
    result = runner.invoke(cli_mod.app, ["fleet", str(empty)])
    assert result.exit_code == 0, result.output
    assert "No repos with .git found" in result.output
