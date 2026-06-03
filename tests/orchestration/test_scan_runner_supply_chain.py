"""scan_runner cross-stack supply-chain step wiring (Plan 12-05, Task 2).

Proves:
  * ``run_scan`` calls ``scan_runner.run_supply_chain`` AFTER ``run_sca``, passing
    the working-tree finding set and ``sca_result.findings``; the returned history
    + promoted MAL findings appear in the final merged findings.
  * the CVE partition input uses the MAL-free ``cve_findings`` (so the aggregate
    SCA findings substitute the MAL-free remainder — no double-count).
  * ``meta.sbom_path`` is stamped from the supply-chain result; on an unavailable
    SBOM ``sbom_path`` is None and the scan still completes (rc 0).
  * an APPLICABLE supply-chain degradation folds a "Supply-chain" disclosure note
    into ``scope_ledger.notes`` and flips ``partial``.

These run the deterministic pipeline with ``--no-agent`` (the root conftest
autouse fixture keeps the agent loop a hermetic no-op) and monkeypatch BOTH
``scan_runner.run_sca`` and ``scan_runner.run_supply_chain`` so no osv / syft /
gitleaks binary or network is touched.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.sca import ScaScanResult
from repo_audit.adapters.supply_chain import SupplyChainResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding


def _cve_finding() -> Finding:
    """An ordinary (non-MAL) CVE finding from the SCA set."""
    return Finding(
        dimension="security",
        severity="major",
        confidence="candidate",
        evidence_type="static",
        source_tool="osv-scanner",
        source_collector="sca",
        rule_id="GHSA-aaaa-bbbb-cccc",
        recommendation="upgrade the dependency",
        evidence=Evidence(
            tool="osv-scanner",
            output_snippet="CVE in left-pad@1.0.0",
            parsed_value={"cve": "GHSA-aaaa-bbbb-cccc"},
        ),
    )


def _mal_promoted() -> Finding:
    """A promoted malicious-package finding (confidence='confirmed')."""
    return Finding(
        dimension="security",
        severity="critical",
        confidence="confirmed",
        evidence_type="static",
        source_tool="osv-scanner",
        source_collector="malicious_package",
        rule_id="MAL-2026-2144",
        recommendation="remove the malicious package immediately",
        confidence_caveat="Confirmed by the OSV malicious-package advisory feed.",
        evidence=Evidence(
            tool="osv-scanner",
            output_snippet="malicious package evil-lib@9.9.9",
            parsed_value={"mal": "MAL-2026-2144"},
        ),
    )


def _history_finding() -> Finding:
    """A net-new history secret finding."""
    return Finding(
        dimension="security",
        severity="major",
        confidence="candidate",
        evidence_type="heuristic",
        source_tool="gitleaks-history",
        source_collector="git_history",
        file="old.env",
        line=2,
        rule_id="aws-access-token",
        recommendation="rotate it",
        evidence=Evidence(
            tool="gitleaks-history",
            output_snippet="aws-access-token [REDACTED:20] at line 2",
            parsed_value={"rule_id": "aws-access-token", "redacted_len": 20},
            line_range=(2, 2),
        ),
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


def _patch_sca(monkeypatch, findings):
    """Stub run_sca so the SCA set is deterministic (includes a MAL + a CVE)."""
    def _sca(repo_path, *, base_env, refresh=False):
        return ScaScanResult(findings=findings, status="ok", notes="sca ok")
    monkeypatch.setattr(scan_runner, "run_sca", _sca, raising=True)


def test_supply_chain_wired_after_sca(fake_repo_on_disk, monkeypatch):
    """run_supply_chain is called after run_sca with working-tree + sca findings."""
    sca_set = [_mal_promoted(), _cve_finding()]  # MAL-* inline before promotion
    _patch_sca(monkeypatch, sca_set)

    seen = {}

    def _supply(repo_path, *, base_env, scan_date, working_tree_findings, sca_findings):
        seen["working_tree_findings"] = working_tree_findings
        seen["sca_findings"] = sca_findings
        # Return the promoted MAL + history on findings; MAL-free cve back.
        return SupplyChainResult(
            findings=[_history_finding(), _mal_promoted()],
            cve_findings=[_cve_finding()],  # MAL-free
            sbom_path="/tmp/reports/repo-sbom-2026-06-03.json",
            status="ok",
            notes="supply-chain ok",
        )

    monkeypatch.setattr(scan_runner, "run_supply_chain", _supply, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    # run_supply_chain received the SCA finding set (for MAL promotion).
    assert "sca_findings" in seen
    assert any((f.rule_id or "").startswith("MAL-") for f in seen["sca_findings"])
    # working_tree_findings was the COLL-03 collector set (a list).
    assert isinstance(seen["working_tree_findings"], list)

    merged = result.scan_report.findings
    # History + promoted MAL appear in the merged findings.
    assert any(f.source_collector == "git_history" for f in merged)
    assert any(
        (f.rule_id or "").startswith("MAL-") and f.confidence == "confirmed"
        for f in merged
    )
    # The CVE finding appears EXACTLY once (the MAL-free cve_findings replaced the
    # raw sca_result.findings — no double-count of MAL, and the CVE survives).
    cve_hits = [f for f in merged if f.rule_id == "GHSA-aaaa-bbbb-cccc"]
    assert len(cve_hits) == 1
    # The promoted MAL is not duplicated (came only from run_supply_chain.findings,
    # not also from the raw sca set).
    mal_hits = [f for f in merged if (f.rule_id or "").startswith("MAL-")]
    assert len(mal_hits) == 1


def test_sbom_path_stamped(fake_repo_on_disk, monkeypatch):
    """meta.sbom_path is stamped from the supply-chain result."""
    _patch_sca(monkeypatch, [])

    def _supply(repo_path, *, base_env, scan_date, working_tree_findings, sca_findings):
        return SupplyChainResult(
            sbom_path="/tmp/reports/repo-sbom-2026-06-03.json", status="ok"
        )

    monkeypatch.setattr(scan_runner, "run_supply_chain", _supply, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.scan_report.meta.sbom_path == "/tmp/reports/repo-sbom-2026-06-03.json"


def test_sbom_unavailable_sbom_path_none(fake_repo_on_disk, monkeypatch):
    """On unavailable SBOM, sbom_path is None and the scan still completes."""
    _patch_sca(monkeypatch, [])

    def _supply(repo_path, *, base_env, scan_date, working_tree_findings, sca_findings):
        return SupplyChainResult(
            sbom_path=None,
            status="unavailable",
            notes="syft absent",
            ledger_notes=["SBOM (unavailable): syft absent"],
        )

    monkeypatch.setattr(scan_runner, "run_supply_chain", _supply, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.rc == 0
    assert result.scan_report.meta.sbom_path is None


def test_supply_chain_degradation_flips_partial_and_discloses(fake_repo_on_disk, monkeypatch):
    """An applicable supply-chain degradation folds a note + flips partial."""
    _patch_sca(monkeypatch, [])

    def _supply(repo_path, *, base_env, scan_date, working_tree_findings, sca_findings):
        return SupplyChainResult(
            status="unavailable",
            notes="supply-chain degraded",
            ledger_notes=["SBOM (unavailable): syft absent"],
        )

    monkeypatch.setattr(scan_runner, "run_supply_chain", _supply, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.scan_report.meta.partial is True
    notes = (result.scan_report.scope_ledger.notes or "").lower()
    assert "supply-chain" in notes
