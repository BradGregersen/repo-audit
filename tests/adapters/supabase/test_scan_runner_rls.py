"""scan_runner cross-stack RLS step + CLI flag wiring tests (Plan 08-05, Task 2).

Proves:
  * ``run_scan`` calls ``scan_runner.run_supabase`` exactly once as a cross-stack
    step (mirroring ``run_sca``), merges its findings, folds its ledger notes +
    provenance into the scope ledger, and threads ``rls_runtime`` / ``rls_pgrls``.
  * an RLS dimension unavailable does NOT abort the scan (graceful degradation).
  * ``cli.py scan()`` exposes ``--rls-runtime`` / ``--rls-pgrls`` and threads them
    into ``run_scan``.
  * the supabase adapter is registered after the ``cli.py`` side-effect import.

These run the deterministic pipeline with ``--no-agent`` and monkeypatch
``scan_runner.run_supabase`` so no docker / node / live DB is touched.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding


def _supa_finding() -> Finding:
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="splinter", output_snippet="present; verify."),
        evidence_type="static",
        confidence="candidate",
        recommendation="present; verify the policy shape before relying on it.",
        source_tool="splinter",
        source_collector="splinter",
        rule_id="rls_disabled_in_public",
    )


@pytest.fixture
def fake_supabase_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot/post-flight work."""
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


def test_run_scan_calls_run_supabase_once_and_merges(
    fake_supabase_repo_on_disk, monkeypatch
):
    """run_supabase is called once cross-stack; findings + ledger notes merged."""
    calls = {"n": 0, "rls_pgrls": None, "rls_runtime": None}

    def _spy_run_supabase(repo_path, *, base_env, rls_pgrls=False, rls_runtime=False):
        from repo_audit.adapters.supabase import SupabaseScanResult

        calls["n"] += 1
        calls["rls_pgrls"] = rls_pgrls
        calls["rls_runtime"] = rls_runtime
        return SupabaseScanResult(
            findings=[_supa_finding()],
            status="ok",
            notes="splinter: 1 finding(s)",
            ledger_notes=["RLS provenance — splinter@abc; layout=supabase/migrations"],
            provenance={"layout": "supabase/migrations"},
        )

    monkeypatch.setattr(scan_runner, "run_supabase", _spy_run_supabase, raising=True)

    result = scan_runner.run_scan(
        fake_supabase_repo_on_disk, no_agent=True, rls_pgrls=True, rls_runtime=False
    )

    assert calls["n"] == 1
    assert calls["rls_pgrls"] is True
    assert calls["rls_runtime"] is False
    # The RLS finding is merged into the report.
    assert any(
        f.rule_id == "rls_disabled_in_public" for f in result.scan_report.findings
    )
    # The ledger notes appear in the scope ledger.
    assert "RLS provenance" in (result.scan_report.scope_ledger.notes or "")


def test_run_scan_threads_runtime_flag(fake_supabase_repo_on_disk, monkeypatch):
    """rls_runtime propagates into run_supabase."""
    seen = {}

    def _spy(repo_path, *, base_env, rls_pgrls=False, rls_runtime=False):
        from repo_audit.adapters.supabase import SupabaseScanResult

        seen["rls_runtime"] = rls_runtime
        return SupabaseScanResult(status="ok")

    monkeypatch.setattr(scan_runner, "run_supabase", _spy, raising=True)
    scan_runner.run_scan(
        fake_supabase_repo_on_disk, no_agent=True, rls_runtime=True
    )
    assert seen["rls_runtime"] is True


def test_rls_unavailable_does_not_abort_scan(
    fake_supabase_repo_on_disk, monkeypatch
):
    """RLS unavailable -> scan still completes, gap disclosed in the ledger."""

    def _unavailable(repo_path, *, base_env, rls_pgrls=False, rls_runtime=False):
        from repo_audit.adapters.supabase import SupabaseScanResult

        return SupabaseScanResult(
            status="unavailable",
            findings=[],
            notes="no migrations",
            ledger_notes=["RLS-01 splinter floor unavailable: no migrations found"],
            provenance={"layout": "none"},
        )

    monkeypatch.setattr(scan_runner, "run_supabase", _unavailable, raising=True)
    result = scan_runner.run_scan(fake_supabase_repo_on_disk, no_agent=True)
    # Scan completes (a report object exists) and discloses the gap.
    assert result.scan_report is not None
    assert "no migrations" in (result.scan_report.scope_ledger.notes or "").lower()
    # partial banner flips on RLS unavailable.
    assert result.scan_report.meta.partial is True


def test_cli_exposes_rls_flags_and_threads_them(monkeypatch):
    """cli.scan exposes --rls-runtime / --rls-pgrls and threads them through."""
    from typer.testing import CliRunner

    from repo_audit import cli

    captured = {}

    def _fake_run_scan(repo, **kwargs):
        captured.update(kwargs)
        # Return a minimal ScanResult-shaped object so the CLI proceeds.
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
        cli.app, ["scan", ".", "--no-agent", "--rls-runtime", "--rls-pgrls"]
    )
    assert result.exit_code == 0, result.output
    assert captured.get("rls_runtime") is True
    assert captured.get("rls_pgrls") is True


def test_supabase_adapter_registered_after_cli_import():
    """Importing cli triggers the supabase side-effect registration."""
    import repo_audit.cli  # noqa: F401 — triggers side-effect imports
    from repo_audit.adapters import get_adapter_registry

    assert "supabase" in get_adapter_registry()
