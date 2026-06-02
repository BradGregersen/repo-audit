"""scan_runner cross-stack MOBILE step + CLI flag wiring tests (Plan 09-05, Task 2).

Proves:
  * ``run_scan`` calls ``scan_runner.run_mobile`` exactly once as a cross-stack
    step (mirroring ``run_sca`` / ``run_supabase``), threads the
    ``mobsf`` / ``mobsf_build`` / ``apk`` kwargs, merges its findings, and folds
    its ledger notes into the scope ledger.
  * Tiers 1+2 run by DEFAULT: the spied step is called with
    ``mobsf=False, mobsf_build=False`` on a plain ``repo-audit scan --no-agent``.
  * the ``--mobsf-build`` flag threads through to ``run_mobile``.
  * ``repo-audit scan --help`` lists ``--mobsf`` / ``--mobsf-build`` / ``--apk``.
  * the mobile adapter is registered after the ``cli.py`` side-effect import.

These run the deterministic pipeline with ``--no-agent`` and monkeypatch
``scan_runner.run_mobile`` so NO real mobsfscan / docker / gradle is touched
(fast + offline). The autouse ``_stub_agent_session`` in the top-level conftest
keeps the agent loop a hermetic no-op.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding


def _mobile_finding() -> Finding:
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="mobsfscan", output_snippet="present; verify."),
        evidence_type="static",
        confidence="candidate",
        recommendation="present; verify the finding before relying on it.",
        source_tool="mobsfscan",
        source_collector="mobsfscan",
        rule_id="android_hardcoded_secret",
    )


@pytest.fixture
def fake_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot / post-flight work."""
    import subprocess

    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    return tmp_path


def test_mobile_step_default_runs_tier1_2(fake_repo_on_disk, monkeypatch):
    """run_mobile is called once with mobsf=False/mobsf_build=False; finding merged."""
    calls = {"n": 0, "mobsf": None, "mobsf_build": None, "apk": "unset"}

    def _spy_run_mobile(repo, *, base_env, mobsf=False, mobsf_build=False, apk=None):
        from repo_audit.adapters.mobile import MobileScanResult

        calls["n"] += 1
        calls["mobsf"] = mobsf
        calls["mobsf_build"] = mobsf_build
        calls["apk"] = apk
        return MobileScanResult(
            findings=[_mobile_finding()],
            status="ok",
            notes="mobsfscan: 1 finding(s)",
            ledger_notes=["Tier-1 mobsfscan: 1 finding(s)"],
        )

    monkeypatch.setattr(scan_runner, "run_mobile", _spy_run_mobile, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert calls["n"] == 1
    assert calls["mobsf"] is False
    assert calls["mobsf_build"] is False
    assert calls["apk"] is None
    # The mobile finding is merged into the report.
    assert any(
        f.rule_id == "android_hardcoded_secret"
        for f in result.scan_report.findings
    )


def test_mobsf_build_flag_threads(fake_repo_on_disk, monkeypatch):
    """mobsf / mobsf_build propagate into run_mobile."""
    seen = {}

    def _spy(repo, *, base_env, mobsf=False, mobsf_build=False, apk=None):
        from repo_audit.adapters.mobile import MobileScanResult

        seen["mobsf"] = mobsf
        seen["mobsf_build"] = mobsf_build
        return MobileScanResult(status="ok")

    monkeypatch.setattr(scan_runner, "run_mobile", _spy, raising=True)
    scan_runner.run_scan(
        fake_repo_on_disk, no_agent=True, mobsf=True, mobsf_build=True, apk=None
    )
    assert seen["mobsf"] is True
    assert seen["mobsf_build"] is True


def test_mobile_unavailable_does_not_abort_scan(fake_repo_on_disk, monkeypatch):
    """A mobile tier unavailable -> scan still completes, gap disclosed."""

    def _unavailable(repo, *, base_env, mobsf=False, mobsf_build=False, apk=None):
        from repo_audit.adapters.mobile import MobileScanResult

        return MobileScanResult(
            status="unavailable",
            findings=[],
            notes="no native android source",
            ledger_notes=["Tier-1 mobsfscan skipped: no native android source"],
        )

    monkeypatch.setattr(scan_runner, "run_mobile", _unavailable, raising=True)
    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.scan_report is not None
    assert "native android source" in (
        result.scan_report.scope_ledger.notes or ""
    ).lower()
    # partial banner flips on a mobile tier unavailable.
    assert result.scan_report.meta.partial is True


def test_cli_flags_present(monkeypatch):
    """repo-audit scan --help lists --mobsf / --mobsf-build / --apk."""
    from typer.testing import CliRunner

    from repo_audit import cli

    runner = CliRunner()
    result = runner.invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    assert "--mobsf" in result.output
    assert "--mobsf-build" in result.output
    assert "--apk" in result.output


def test_cli_threads_mobile_flags(monkeypatch):
    """cli.scan threads --mobsf / --mobsf-build into run_scan."""
    from typer.testing import CliRunner

    from repo_audit import cli

    captured = {}

    def _fake_run_scan(repo, **kwargs):
        captured.update(kwargs)
        from repo_audit.orchestration.scan_runner import ScanResult
        from repo_audit.schema.report import ReportMeta, ScanReport

        meta = ReportMeta(
            repo_slug="x",
            commit_sha="UNCOMMITTED",
            scan_date=__import__("datetime").date.today(),
            tool_version="0",
        )
        return ScanResult(
            scan_report=ScanReport(meta=meta),
            md_path=Path("/tmp/x.md"),
            json_path=Path("/tmp/x.json"),
            rc=0,
            agent_status=None,
        )

    monkeypatch.setattr(cli, "run_scan", _fake_run_scan, raising=True)
    runner = CliRunner()
    result = runner.invoke(
        cli.app, ["scan", ".", "--no-agent", "--mobsf", "--mobsf-build"]
    )
    assert result.exit_code == 0, result.output
    assert captured.get("mobsf") is True
    assert captured.get("mobsf_build") is True


def test_mobile_adapter_registered_after_cli_import():
    """Importing cli triggers the mobile side-effect registration."""
    import repo_audit.cli  # noqa: F401 — triggers side-effect imports
    from repo_audit.adapters import get_adapter_registry

    assert "mobile" in get_adapter_registry()
