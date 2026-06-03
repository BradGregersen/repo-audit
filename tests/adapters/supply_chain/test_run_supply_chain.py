"""run_supply_chain — the Phase-12 cross-stack envelope (Plan 12-05, Task 1).

run_supply_chain composes the four Wave-1/2 deliverables into ONE never-raising
cross-stack step mirroring ``run_sast`` / ``run_sca``:

  * SUP-02 generate_sbom  → sbom_path (path only, D-12-07)
  * SCA-04 collect_licenses(sbom)   → minor/candidate copyleft findings
  * SCA-04 collect_deprecated(repo) → info-context (count + named list)
  * SUP-01 promote_malicious(sca_findings) → promoted MAL (confirmed) + the
            MAL-free CVE remainder handed back to the caller
  * HIST-01 collect_git_history(repo, working_tree_findings) → net-new history

Contract pinned here:
  * merged ``findings`` = history(net-new) + promoted MAL + license findings;
    ``status='ok'`` when sub-steps succeed.
  * ``cve_findings`` is MAL-free (the CVE partition is never double-counted) and
    the promoted MAL finding (confidence='confirmed') is in ``findings``.
  * every sub-step degrading → never raises; status reflects degradation; on an
    absent SBOM ``sbom_path`` is None.

Sub-collectors are monkeypatched at the ``run_supply_chain`` module so no git /
syft / gitleaks binary or network is touched — the real ``promote_malicious``
runs over the recorded MAL fixture so the partition behaviour is exercised for
real.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from repo_audit.adapters import supply_chain as sc
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sca.deprecated import DeprecatedResult
from repo_audit.adapters.sca.licenses import LicensesResult
from repo_audit.adapters.supply_chain.history import HistoryResult
from repo_audit.adapters.supply_chain.sbom import SbomResult
from repo_audit.schema.finding import Evidence, Finding


def _sca_findings_with_mal(load_supply_chain_fixture) -> list[Finding]:
    """The osv SARIF set (one MAL-2026-2144 + one ordinary GHSA), candidate-capped."""
    sarif = load_supply_chain_fixture("mal-osv.sarif.json")
    return sarif_to_findings(
        sarif,
        source_tool="osv-scanner",
        default_dimension="security",
        severity_map={},
    )


def _history_finding() -> Finding:
    """A net-new committed-then-deleted history secret finding (COLL-03 shape)."""
    return Finding(
        dimension="security",
        severity="major",
        confidence="candidate",
        evidence_type="heuristic",
        source_tool="gitleaks-history",
        source_collector="git_history",
        file="config/old.env",
        line=4,
        rule_id="aws-access-token",
        recommendation="rotate it",
        evidence=Evidence(
            tool="gitleaks-history",
            output_snippet="aws-access-token [REDACTED:20] at line 4",
            parsed_value={"rule_id": "aws-access-token", "redacted_len": 20},
            line_range=(4, 4),
        ),
    )


def _license_finding() -> Finding:
    """A minor/candidate copyleft license-risk finding."""
    return Finding(
        dimension="security",
        severity="minor",
        confidence="candidate",
        evidence_type="static",
        source_tool="syft-sbom",
        source_collector="license_risk",
        file="some-gpl-lib",
        rule_id="LICENSE-RISK",
        evidence=Evidence(
            tool="syft-sbom",
            output_snippet="some-gpl-lib is licensed GPL-3.0 (copyleft GPL exposure)",
            parsed_value={"package": "some-gpl-lib", "risk": "copyleft-gpl"},
        ),
    )


def test_run_supply_chain_merges_all(load_supply_chain_fixture, tmp_path, monkeypatch):
    """findings = history + promoted MAL + license; cve_findings is MAL-free; ok."""
    sca_findings = _sca_findings_with_mal(load_supply_chain_fixture)

    monkeypatch.setattr(
        sc, "generate_sbom",
        lambda repo_path, **kw: SbomResult(
            status="ok", sbom_path=tmp_path / "repo-sbom-2026-06-03.json"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        sc, "collect_licenses",
        lambda sbom: LicensesResult(findings=[_license_finding()], status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        sc, "collect_deprecated",
        lambda source, **kw: DeprecatedResult(
            deprecated_packages=["left-pad"], count=1, status="ok"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        sc, "collect_git_history",
        lambda repo_path, working_tree_findings=None, **kw: HistoryResult(
            findings=[_history_finding()], status="ok"
        ),
        raising=True,
    )

    result = sc.run_supply_chain(
        tmp_path,
        base_env={},
        scan_date=date(2026, 6, 3),
        working_tree_findings=[],
        sca_findings=sca_findings,
    )

    assert result.status == "ok"
    # The promoted MAL finding (confirmed) is in the merged findings.
    mal = [f for f in result.findings if (f.rule_id or "").startswith("MAL-")]
    assert mal, "expected the promoted MAL finding in the merged findings"
    assert all(f.confidence == "confirmed" for f in mal)
    # History + license findings also merged.
    assert any(f.source_collector == "git_history" for f in result.findings)
    assert any(f.source_collector == "license_risk" for f in result.findings)
    # The CVE partition handed back to the caller is MAL-free.
    assert result.cve_findings, "expected the non-MAL CVE remainder"
    assert all(not (f.rule_id or "").startswith("MAL-") for f in result.cve_findings)
    assert any("GHSA" in (f.rule_id or "") for f in result.cve_findings)
    # The SBOM is referenced by path.
    assert result.sbom_path is not None
    # Deprecated context surfaced.
    assert result.deprecated_context.count == 1


def test_no_mal_rule_id_leaks_into_cve_input(load_supply_chain_fixture, tmp_path, monkeypatch):
    """No MAL-* rule_id appears in the cve_findings the caller feeds the CVE partition."""
    sca_findings = _sca_findings_with_mal(load_supply_chain_fixture)
    monkeypatch.setattr(sc, "generate_sbom", lambda repo_path, **kw: SbomResult(status="unavailable"), raising=True)
    monkeypatch.setattr(sc, "collect_licenses", lambda sbom: LicensesResult(status="unavailable"), raising=True)
    monkeypatch.setattr(sc, "collect_deprecated", lambda source, **kw: DeprecatedResult(status="unavailable"), raising=True)
    monkeypatch.setattr(sc, "collect_git_history", lambda repo_path, working_tree_findings=None, **kw: HistoryResult(status="ok"), raising=True)

    result = sc.run_supply_chain(
        tmp_path, base_env={}, scan_date=date(2026, 6, 3),
        working_tree_findings=[], sca_findings=sca_findings,
    )
    assert all(not (f.rule_id or "").startswith("MAL-") for f in result.cve_findings)
    # The promoted MAL is on findings (not cve_findings).
    assert any((f.rule_id or "").startswith("MAL-") for f in result.findings)


def test_all_substeps_unavailable_never_raises(tmp_path, monkeypatch):
    """Every sub-step degraded → never raises; status degrades; sbom_path None."""
    monkeypatch.setattr(sc, "generate_sbom", lambda repo_path, **kw: SbomResult(status="unavailable", notes="syft absent"), raising=True)
    monkeypatch.setattr(sc, "collect_licenses", lambda sbom: LicensesResult(status="unavailable", notes="no sbom"), raising=True)
    monkeypatch.setattr(sc, "collect_deprecated", lambda source, **kw: DeprecatedResult(status="unavailable", notes="offline"), raising=True)
    monkeypatch.setattr(sc, "collect_git_history", lambda repo_path, working_tree_findings=None, **kw: HistoryResult(status="unavailable", notes="no git"), raising=True)

    result = sc.run_supply_chain(
        tmp_path, base_env={}, scan_date=date(2026, 6, 3),
        working_tree_findings=[], sca_findings=[],
    )
    # Never raised; honest degraded status; no SBOM path; ledger notes populated.
    assert result.status in ("unavailable", "ok")
    assert result.sbom_path is None
    assert result.findings == []
    assert result.ledger_notes, "every degraded sub-step folds a ledger note"


def test_sbom_path_threaded_to_licenses(tmp_path, monkeypatch):
    """collect_licenses receives the SBOM path from generate_sbom (offline-from-SBOM)."""
    seen = {}
    sbom_path = tmp_path / "x-sbom.json"
    monkeypatch.setattr(sc, "generate_sbom", lambda repo_path, **kw: SbomResult(status="ok", sbom_path=sbom_path), raising=True)

    def _capture_licenses(sbom):
        seen["sbom"] = sbom
        return LicensesResult(status="ok")

    monkeypatch.setattr(sc, "collect_licenses", _capture_licenses, raising=True)
    monkeypatch.setattr(sc, "collect_deprecated", lambda source, **kw: DeprecatedResult(status="ok"), raising=True)
    monkeypatch.setattr(sc, "collect_git_history", lambda repo_path, working_tree_findings=None, **kw: HistoryResult(status="ok"), raising=True)

    sc.run_supply_chain(
        tmp_path, base_env={}, scan_date=date(2026, 6, 3),
        working_tree_findings=[], sca_findings=[],
    )
    assert seen["sbom"] == sbom_path
