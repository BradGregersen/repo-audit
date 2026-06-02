"""scan_runner cross-stack SAST step + --no-sast wiring tests (Plan 10-04, Task 3).

Proves:
  * ``run_scan`` calls ``scan_runner.run_sast`` as a cross-stack step (mirroring
    ``run_sca`` / ``run_supabase`` / ``run_mobile``), merges its findings, EXTENDS
    ``meta.feed_provenance`` with the D-10-02 SAST stamp (alongside any SCA stamp),
    and folds its status/notes into the scope ledger + the partial flag (SAFE-08).
  * a SAST dimension unavailable does NOT abort the scan (graceful degradation).
  * ``--no-sast`` (``sast=False``) skips the step entirely — ``run_sast`` is never
    invoked — and the report still writes.

These run the deterministic pipeline with ``--no-agent`` (the root conftest
``_stub_agent_session`` autouse fixture keeps the agent loop a hermetic no-op too)
and monkeypatch ``scan_runner.run_sast`` so no Semgrep binary / network is touched.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone

import pytest

from repo_audit.adapters.sast import SastScanResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import FeedProvenance


def _sast_finding() -> Finding:
    """A representative SAST finding (security / static / candidate)."""
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(
            tool="semgrep",
            output_snippet="os.system('rm -rf ' + user_input)",
            parsed_value={"owasp": ["A03:2021 - Injection"]},
        ),
        evidence_type="static",
        confidence="candidate",
        recommendation="Avoid building shell commands from untrusted input; verify.",
        source_tool="semgrep",
        rule_id="python.lang.security.audit.dangerous-os-command",
    )


def _sast_provenance() -> FeedProvenance:
    """The D-10-02 SAST stamp (runtime-fetch; db_snapshot_date=None)."""
    return FeedProvenance(
        feed="semgrep-registry",
        scanner="semgrep",
        scanner_version="1.163.0",
        db_snapshot_date=None,
        queried_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
    )


@pytest.fixture
def fake_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot / post-flight checks work."""
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    return tmp_path


def test_run_sast_findings_fold(fake_repo_on_disk, monkeypatch):
    """run_sast is called cross-stack; its finding + provenance fold into the report."""
    calls = {"n": 0}

    def _spy_run_sast(repo_path, *, base_env, detection):
        calls["n"] += 1
        return SastScanResult(
            findings=[_sast_finding()],
            feed_provenance=[_sast_provenance()],
            status="ok",
            notes="semgrep: 1 finding(s)",
        )

    monkeypatch.setattr(scan_runner, "run_sast", _spy_run_sast, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert calls["n"] == 1
    # The SAST finding flowed into the merged report findings.
    assert any(
        f.source_tool == "semgrep"
        and f.rule_id == "python.lang.security.audit.dangerous-os-command"
        for f in result.scan_report.findings
    )
    # The D-10-02 SAST stamp joins meta.feed_provenance (alongside any SCA stamp,
    # which is empty in a no-lockfile repo here).
    assert any(
        p.feed == "semgrep-registry" and p.scanner == "semgrep"
        and p.db_snapshot_date is None
        for p in result.scan_report.meta.feed_provenance
    )


def test_run_sast_unavailable_graceful(fake_repo_on_disk, monkeypatch):
    """SAST unavailable -> scan still completes, partial flips, ledger discloses it."""

    def _unavailable(repo_path, *, base_env, detection):
        return SastScanResult(
            findings=[],
            feed_provenance=[],
            status="unavailable",
            notes="semgrep not found (vendor + node_modules + PATH miss)",
        )

    monkeypatch.setattr(scan_runner, "run_sast", _unavailable, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    # Scan completes (a report object exists) at rc 0 — no raise, no hang.
    assert result.rc == 0
    assert result.scan_report is not None
    # partial flips on SAST unavailable (SAFE-08 honesty).
    assert result.scan_report.meta.partial is True
    # The SAST unavailability is disclosed in the scope ledger notes.
    assert "sast" in (result.scan_report.scope_ledger.notes or "").lower()
    # No SAST stamp was added (nothing reproducible).
    assert not any(
        p.scanner == "semgrep" for p in result.scan_report.meta.feed_provenance
    )


def test_no_sast_skips(fake_repo_on_disk, monkeypatch):
    """run_scan(sast=False) NEVER invokes run_sast; the report still writes."""
    called = {"hit": False}

    def _must_not_run(repo_path, *, base_env, detection):
        called["hit"] = True
        return SastScanResult(status="ok")

    monkeypatch.setattr(scan_runner, "run_sast", _must_not_run, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True, sast=False)

    assert called["hit"] is False
    # The report still writes (rc 0) and is a real ScanReport.
    assert result.rc == 0
    assert result.scan_report is not None
