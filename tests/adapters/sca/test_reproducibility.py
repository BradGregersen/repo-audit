"""Task 4 (Plan 07-05): SC-5 reproducibility — LIVE-binary integration test.

All tests here are ``@pytest.mark.integration`` (gated; excluded from the default
unit tier). They drive the REAL vendored osv-scanner + grype binaries against a
known-vulnerable ``requirements.txt`` (urllib3==1.23.0 — continuity with the Plan
02 fixture subject) and prove the phase's reproducibility contract:

    SC-5  two PINNED runs on an unchanged checkout → IDENTICAL findings.
    Pinned = NO network: the scan argv passes ``--offline-vulnerabilities`` and
            NEVER ``--download-offline-databases`` (only --refresh-vuln-db does).
    Pitfall 7: ``queried_at`` lives ONLY on FeedProvenance, never on a Finding.

These catch argv-shape bugs the recorded-fixture unit tests cannot — the Phase-3
lesson (each adapter needs at least one live-binary integration test).

SKIP discipline: when the persistent vuln-DB is unseeded AND we cannot reach the
network to seed it, the test SKIPs cleanly (the first-run seed is the documented
manual step, VALIDATION.md). When the vendored binaries are absent it SKIPs too.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import repo_audit.adapters.sca.osv as osv_mod
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sca import run_sca
from repo_audit.adapters.sca.db_env import sca_db_dir

pytestmark = pytest.mark.integration

_REQUIREMENTS = "urllib3==1.23.0\n"


def _binaries_present(repo: Path) -> bool:
    return (
        resolve_tool("osv-scanner", repo) is not None
        and resolve_tool("grype", repo) is not None
    )


def _osv_db_seeded() -> bool:
    osv_dir = sca_db_dir() / "osv"
    # Require an actual DB file, not a half-created empty ecosystem subdir.
    return osv_dir.is_dir() and any(p.is_file() for p in osv_dir.rglob("*"))


@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(_REQUIREMENTS, encoding="utf-8")
    return tmp_path


def _guard(repo: Path) -> None:
    if not _binaries_present(repo):
        pytest.skip("vendored osv-scanner/grype not present")
    if not _osv_db_seeded():
        pytest.skip(
            "vuln-DB unseeded; first-run seed is a manual/network step (VALIDATION.md)"
        )


def test_two_pinned_runs_yield_identical_findings(vuln_repo):
    """SC-5: identical checkout + identical snapshot → identical findings."""
    _guard(vuln_repo)
    import os

    run1 = run_sca(vuln_repo, base_env=os.environ.copy())
    run2 = run_sca(vuln_repo, base_env=os.environ.copy())

    assert run1.status == "ok"
    assert run2.status == "ok"

    dumped1 = [f.model_dump() for f in run1.findings]
    dumped2 = [f.model_dump() for f in run2.findings]
    assert dumped1 == dumped2  # element-for-element, deterministic sort
    assert len(run1.findings) > 0  # urllib3 1.23.0 is known-vulnerable


def test_queried_at_never_leaks_onto_a_finding(vuln_repo):
    """Pitfall 7: queried_at lives ONLY on FeedProvenance, never on a Finding."""
    _guard(vuln_repo)
    import os

    result = run_sca(vuln_repo, base_env=os.environ.copy())
    for finding in result.findings:
        dumped = finding.model_dump()
        assert "queried_at" not in dumped
        # Also not buried in the evidence parsed_value.
        assert "queried_at" not in finding.evidence.parsed_value
    # But it IS present on every FeedProvenance entry.
    assert result.feed_provenance
    for prov in result.feed_provenance:
        assert prov.queried_at is not None


def test_pinned_scan_argv_is_offline_no_download(vuln_repo, monkeypatch):
    """Pinned mode passes --offline-vulnerabilities and NOT --download-offline-databases."""
    _guard(vuln_repo)
    import os

    recorded: list[list[str]] = []
    real_run_tool = osv_mod.run_tool

    def spy(argv, *, env, cwd, timeout_seconds):
        recorded.append(list(argv))
        return real_run_tool(argv, env=env, cwd=cwd, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(osv_mod, "run_tool", spy)

    run_sca(vuln_repo, base_env=os.environ.copy(), refresh=False)

    assert recorded, "osv run_tool was never invoked"
    flat = [tok for argv in recorded for tok in argv]
    assert "--offline-vulnerabilities" in flat
    assert "--download-offline-databases" not in flat  # pinned = no network


def test_feed_provenance_stamped_with_version_and_snapshot(vuln_repo):
    """FeedProvenance carries the osv scanner_version + a db_snapshot_date."""
    _guard(vuln_repo)
    import os

    result = run_sca(vuln_repo, base_env=os.environ.copy())
    osv_entry = next(p for p in result.feed_provenance if p.scanner == "osv-scanner")
    assert osv_entry.scanner_version  # non-empty (e.g. "2.3.8")
    assert osv_entry.db_snapshot_date is not None  # mtime of the seeded DB (A2)
