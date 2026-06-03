"""SUP-01 — malicious-package promotion over the osv MAL-* advisories (Wave 1).

Wave-0 ``importorskip`` stub: SKIPPED until
``repo_audit.adapters.sca.malicious`` lands, then ACTIVE.

Contract under test (RESEARCH Test Map, D-12-05/06 + SAFE-01):
  * a MAL-* rule_id finding is promoted to confidence='confirmed' with a
    FAITHFUL critical/blocker severity (D-12-06 — MAL is authoritative, near-zero
    FP, so it is the SOLE confirmed-promotion path; CVEs stay candidate-capped),
  * the promotion still carries a confidence caveat (SAFE-01),
  * MAL-* findings are EXCLUDED from the ordinary CVE partition (no double-count).

Loads the recorded ``mal-osv.sarif.json`` fixture (one bare MAL-2026-2144 result
plus one ordinary GHSA result) so both populations are present.
"""
from __future__ import annotations

import pytest

from repo_audit.adapters.sarif.parser import sarif_to_findings

malicious = pytest.importorskip(
    "repo_audit.adapters.sca.malicious",
    reason="Wave 1 not yet landed — sca.malicious missing",
)


def _mal_findings(load_supply_chain_fixture):
    """Parse the MAL fixture SARIF into Findings via the single FND-01 path."""
    sarif = load_supply_chain_fixture("mal-osv.sarif.json")
    return sarif_to_findings(
        sarif,
        source_tool="osv-scanner",
        default_dimension="security",
        severity_map={},
    )


def _promote(findings):
    """Invoke the Wave-1 MAL promotion/partition entry point, tolerating names."""
    for name in ("promote_malicious", "classify_malicious", "partition_malicious"):
        fn = getattr(malicious, name, None)
        if fn is not None:
            return fn(findings)
    pytest.fail("sca.malicious exposes no promotion entry point")


def test_mal_promoted_confirmed_faithful_severity(load_supply_chain_fixture):
    """D-12-06: the MAL-* finding is confidence='confirmed' + faithful crit/blocker."""
    result = _promote(_mal_findings(load_supply_chain_fixture))
    mal = [
        f
        for f in getattr(result, "findings", result)
        if (f.rule_id or "").startswith("MAL-")
    ]
    assert mal, "expected the MAL-2026-2144 finding to survive promotion"
    for f in mal:
        assert f.confidence == "confirmed"
        assert f.severity in ("critical", "blocker")


def test_mal_carries_confidence_caveat(load_supply_chain_fixture):
    """SAFE-01: a promoted MAL finding still carries a confidence caveat."""
    result = _promote(_mal_findings(load_supply_chain_fixture))
    mal = [
        f
        for f in getattr(result, "findings", result)
        if (f.rule_id or "").startswith("MAL-")
    ]
    assert mal
    for f in mal:
        assert getattr(f, "confidence_caveat", None), (
            "promoted MAL finding must keep a confidence_caveat (SAFE-01)"
        )


def test_mal_excluded_from_cve_partition(load_supply_chain_fixture):
    """MAL-* findings are NOT double-counted in the ordinary CVE partition."""
    findings = _mal_findings(load_supply_chain_fixture)
    result = _promote(findings)
    # The Wave-1 step exposes the non-MAL (CVE) population separately; its
    # exact accessor is owned by Wave 1, so accept a few shapes.
    cve_partition = (
        getattr(result, "cve_findings", None)
        or getattr(result, "non_malicious", None)
    )
    assert cve_partition is not None, (
        "Wave 1 must expose the CVE partition separately from MAL"
    )
    assert all(not (f.rule_id or "").startswith("MAL-") for f in cve_partition)
    # And the GHSA CVE finding is present in that partition.
    assert any("GHSA" in (f.rule_id or "") for f in cve_partition)
