"""Task 3 (Plan 07-05): run_sca orchestration + scan_runner wiring + CLI flag.

run_sca composes osv + grype + corroborate + partition + provenance behind the
persistent DB env. scan_runner runs it as a cross-stack step, merges its
findings, and stamps meta.feed_provenance. --refresh-vuln-db is the sole advance
path.
"""
from __future__ import annotations

from datetime import datetime, timezone

import repo_audit.adapters.sca as sca
import repo_audit.adapters.sca.refresh as refreshmod
from repo_audit.adapters.sca import ScaScanResult, run_sca
from repo_audit.adapters.sca.grype import GrypeResult
from repo_audit.adapters.sca.osv import OsvResult
from repo_audit.schema.finding import Evidence, Finding


def _finding(cve: str) -> Finding:
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="osv-scanner", output_snippet="x"),
        evidence_type="static",
        confidence="candidate",
        source_tool="osv-scanner",
        rule_id=cve,
    )


def test_osv_unavailable_makes_dimension_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sca, "collect_osv",
        lambda repo, env: OsvResult(status="unavailable", findings=[], notes="missing"),
    )
    # grype must not even be consulted when osv (the floor) is unavailable.
    monkeypatch.setattr(
        sca, "collect_grype",
        lambda repo, env: (_ for _ in ()).throw(AssertionError("not reached")),
    )
    result = run_sca(tmp_path, base_env={"PATH": "/usr/bin"})
    assert isinstance(result, ScaScanResult)
    assert result.status == "unavailable"
    assert result.findings == []
    assert result.feed_provenance == []


def test_feed_provenance_one_entry_when_grype_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sca, "collect_osv",
        lambda repo, env: OsvResult(status="ok", scanner_version="2.3.8", findings=[_finding("CVE-2019-11236")]),
    )
    monkeypatch.setattr(
        sca, "collect_grype",
        lambda repo, env: GrypeResult(status="unavailable", findings=[]),
    )
    result = run_sca(tmp_path, base_env={"PATH": "/usr/bin"})
    assert result.status == "ok"
    assert len(result.feed_provenance) == 1
    assert result.feed_provenance[0].scanner == "osv-scanner"
    assert len(result.findings) == 1


def test_feed_provenance_two_entries_when_grype_present(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sca, "collect_osv",
        lambda repo, env: OsvResult(status="ok", scanner_version="2.3.8", findings=[_finding("CVE-2019-11236")]),
    )
    monkeypatch.setattr(
        sca, "collect_grype",
        lambda repo, env: GrypeResult(status="ok", scanner_version="0.112.0", db_snapshot_date="2026-06-01T08:11:23Z", findings=[]),
    )
    result = run_sca(tmp_path, base_env={"PATH": "/usr/bin"})
    assert {p.scanner for p in result.feed_provenance} == {"osv-scanner", "grype"}


def test_normal_scan_does_not_refresh(monkeypatch, tmp_path):
    """A normal run_sca (refresh=False) NEVER calls refresh_vuln_db."""
    monkeypatch.setattr(
        sca, "collect_osv",
        lambda repo, env: OsvResult(status="ok", scanner_version="2.3.8", findings=[]),
    )
    monkeypatch.setattr(
        sca, "collect_grype",
        lambda repo, env: GrypeResult(status="unavailable", findings=[]),
    )
    called = {"refresh": False}
    monkeypatch.setattr(
        sca, "refresh_vuln_db",
        lambda env: called.__setitem__("refresh", True) or refreshmod.ScaRefreshResult(status="ok"),
    )
    # Pre-seed the DB dirs so the first-run seed path is NOT triggered.
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    from repo_audit.adapters.sca.db_env import sca_db_dir
    (sca_db_dir() / "osv").mkdir(parents=True, exist_ok=True)
    (sca_db_dir() / "grype").mkdir(parents=True, exist_ok=True)
    (sca_db_dir() / "osv" / "all.zip").write_bytes(b"x")
    (sca_db_dir() / "grype" / "vulnerability.db").write_bytes(b"x")

    run_sca(tmp_path, base_env={"PATH": "/usr/bin"}, refresh=False)
    assert called["refresh"] is False


def test_refresh_true_advances_first(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sca, "collect_osv",
        lambda repo, env: OsvResult(status="ok", scanner_version="2.3.8", findings=[]),
    )
    monkeypatch.setattr(
        sca, "collect_grype",
        lambda repo, env: GrypeResult(status="unavailable", findings=[]),
    )
    called = {"refresh": False}
    monkeypatch.setattr(
        sca, "refresh_vuln_db",
        lambda env: called.__setitem__("refresh", True) or refreshmod.ScaRefreshResult(status="ok"),
    )
    run_sca(tmp_path, base_env={"PATH": "/usr/bin"}, refresh=True)
    assert called["refresh"] is True


def test_scan_runner_stamps_feed_provenance(monkeypatch, tmp_path):
    """run_scan wires the SCA step and sets meta.feed_provenance."""
    import repo_audit.orchestration.scan_runner as sr

    captured = {}

    def fake_run_sca(repo_path, *, base_env, refresh=False):
        captured["called"] = True
        from repo_audit.schema.report import FeedProvenance
        return ScaScanResult(
            findings=[_finding("CVE-2019-11236")],
            partition=None,
            feed_provenance=[
                FeedProvenance(
                    feed="OSV", scanner="osv-scanner", scanner_version="2.3.8",
                    queried_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
                )
            ],
            status="ok",
            notes="",
        )

    monkeypatch.setattr(sr, "run_sca", fake_run_sca)
    # Build a minimal git repo so head_sha / snapshot work.
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "requirements.txt").write_text("urllib3==1.23.0\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
        cwd=tmp_path, check=True,
    )

    result = sr.run_scan(tmp_path, no_agent=True)
    assert captured.get("called") is True
    assert len(result.scan_report.meta.feed_provenance) == 1
    # The SCA finding flowed into the merged set.
    assert any(f.rule_id == "CVE-2019-11236" for f in result.scan_report.findings)
