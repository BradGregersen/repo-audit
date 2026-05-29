"""Plan 05-01 Task 1 — run_scan() pipeline-extraction parity guard.

run_scan() is the single source of truth for the single-repo scan pipeline
(RESEARCH Pattern 2). ``repo-audit scan`` (cli.py) and ``repo-audit fleet`` (Plan 05) both
call it. These tests assert:

  (a) run_scan() returns a fully-populated ScanResult over the fake_repo
      fixture, run deterministically/offline via no_agent=True.
  (b) the extraction preserved the observable CLI surface — `repo-audit scan` exit
      codes (0 success / 2 secret-lint / 3 completion-honesty) and the
      stdout/stderr surfaces are unchanged (RESEARCH Assumption A2). These
      mirror the CliRunner patterns in tests/test_cli.py.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.orchestration import ScanResult, run_scan
from repo_audit.schema.report import ScanReport


# --- (a) run_scan() returns a fully-populated ScanResult ---


def test_run_scan_returns_populated_scan_result(fake_repo):
    """run_scan(no_agent=True) over fake_repo → ScanResult with all fields set."""
    repo = fake_repo({"README.md": "# x\n"}, name="runscan-basic")
    result = run_scan(repo, no_agent=True)

    assert isinstance(result, ScanResult)
    assert isinstance(result.scan_report, ScanReport)
    assert result.rc == 0
    # Sidecar pair was written to docs/state-reports/.
    assert isinstance(result.md_path, Path)
    assert isinstance(result.json_path, Path)
    assert result.md_path.exists()
    assert result.json_path.exists()
    assert result.md_path.suffix == ".md"
    assert result.json_path.suffix == ".json"
    # --no-agent → session skipped → agent_status stays None (deterministic).
    assert result.agent_status is None
    # Clean read-only run over a fresh fixture → no integrity offenders.
    assert result.offenders == []
    # Round-trips: the written JSON parses back as a ScanReport.
    ScanReport.model_validate_json(result.json_path.read_text(encoding="utf-8"))


def test_run_scan_writes_only_under_state_reports(fake_repo):
    """REP-03 / Pitfall 7 — the only writes land in docs/state-reports/."""
    repo = fake_repo({"README.md": "# x\n", "src/a.py": "x=1\n"}, name="runscan-ro")
    result = run_scan(repo, no_agent=True)
    assert result.offenders == [], (
        f"run_scan modified files outside docs/state-reports/: {result.offenders}"
    )
    state_dir = repo / "docs" / "state-reports"
    assert result.md_path.parent == state_dir
    assert result.json_path.parent == state_dir


def test_run_scan_resolves_relative_repo_path(fake_repo):
    """run_scan accepts a path and resolves it (slug derived from resolved path)."""
    repo = fake_repo({"README.md": "# x\n"}, name="runscan-slug")
    result = run_scan(repo, no_agent=True)
    assert result.scan_report.meta.repo_slug == "runscan-slug"


# --- (b) observable CLI behavior is unchanged after the extraction ---


def test_scan_exit_0_success(runner, fake_repo):
    """A clean scan exits 0 and prints the two Wrote lines (parity with pre-refactor)."""
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="parity-ok")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    assert "Wrote " in result.stdout
    md_files = list((repo / "docs" / "state-reports").glob("*.md"))
    json_files = list((repo / "docs" / "state-reports").glob("*.json"))
    assert len(md_files) == 1
    assert len(json_files) == 1


def test_scan_exit_2_secret_lint(runner, fake_repo, monkeypatch):
    """rc=2 (secret-lint refused) propagates as exit code 2, no Wrote lines."""
    from repo_audit.cli import app
    from repo_audit.orchestration import scan_runner as runner_mod

    # Force render_and_write to report the secret-lint refusal code.
    monkeypatch.setattr(runner_mod, "render_and_write", lambda *a, **k: 2)
    repo = fake_repo({"README.md": "# x\n"}, name="parity-secret")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 2
    assert "Wrote " not in result.stdout


def test_scan_exit_3_completion_honesty(runner, fake_repo, monkeypatch):
    """rc=3 (completion-honesty refused) propagates as exit code 3, no Wrote lines."""
    from repo_audit.cli import app
    from repo_audit.orchestration import scan_runner as runner_mod

    monkeypatch.setattr(runner_mod, "render_and_write", lambda *a, **k: 3)
    repo = fake_repo({"README.md": "# x\n"}, name="parity-honesty")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 3
    assert "Wrote " not in result.stdout


def test_scan_integrity_alert_surface_unchanged(runner, fake_repo, monkeypatch):
    """When run_scan reports offenders, the CLI still emits the INTEGRITY ALERT block."""
    from repo_audit.cli import app
    from repo_audit.orchestration import scan_runner as runner_mod

    monkeypatch.setattr(
        runner_mod,
        "diff_git_status",
        lambda pre, post: ["?? .eslintcache"],
    )
    repo = fake_repo({"README.md": "# x\n"}, name="parity-integrity")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    assert "INTEGRITY ALERT" in (result.stderr or "")
    assert ".eslintcache" in (result.stderr or "")
