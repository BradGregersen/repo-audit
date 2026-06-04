"""scan_runner cross-stack run_cicd wiring contract stubs (Plan 13-01 Task 3).

Gated on ``scan_runner.run_cicd`` (Plan 04 adds the wiring + the attribute), so a
module-level ``skipif`` activates these the instant Plan 04 lands — the
SKIPPED->ACTIVE-on-landing discipline. Mirrors
``tests/orchestration/test_scan_runner_sast.py`` (the run_* spy pattern +
``fake_repo_on_disk`` git-seeded fixture).

Function names (``test_run_scan_calls_run_cicd`` /
``test_no_cicd_files_does_not_flip_partial``) match 13-VALIDATION.md and the plan
spec; do NOT rename.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.orchestration import scan_runner

pytestmark = pytest.mark.skipif(
    not hasattr(scan_runner, "run_cicd"),
    reason="Wave 2 (Plan 04) not yet landed — scan_runner.run_cicd missing",
)


@pytest.fixture
def fake_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot / post-flight checks work."""
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-q", "-m", "init",
        ],
        check=True,
    )
    return tmp_path


def test_run_scan_calls_run_cicd(fake_repo_on_disk, monkeypatch):
    """run_scan calls scan_runner.run_cicd; its finding folds + 'ci/cd' hits ledger notes.

    Wave-2 contract outline (activates when scan_runner.run_cicd lands):
      - build a CicdScanResult with one Finding + status="ok"
      - monkeypatch.setattr(scan_runner, "run_cicd", spy, raising=True)
      - result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
      - assert the spy was called exactly once
      - assert the CI/CD finding folded into result.scan_report.findings
      - assert "ci/cd" in result.scan_report.scope_ledger.notes.lower()
    """
    raise NotImplementedError("Wave-2 run_cicd wiring contract — fill when scan_runner.run_cicd lands")


def test_no_cicd_files_does_not_flip_partial(fake_repo_on_disk, monkeypatch):
    """A not_applicable run_cicd (no CI/CD files) does NOT set meta.partial (D-13-05).

    Wave-2 contract outline:
      - spy returns CicdScanResult(findings=[], status="not_applicable", notes=...)
      - result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
      - assert result.rc == 0 and result.scan_report is not None
      - assert result.scan_report.meta.partial is False  (a no-files / not_applicable
        step is disclosed but is NOT an applicable degradation — _phase11_step_degraded
        swallows it; only tool-absent-when-files-present / timeout flips partial)
    """
    raise NotImplementedError("Wave-2 run_cicd not-applicable contract — fill when scan_runner.run_cicd lands")
