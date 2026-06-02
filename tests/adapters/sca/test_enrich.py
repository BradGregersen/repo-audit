"""enrich.py unit tests (SCA-03) — direct/transitive + fix from osv native JSON.

Contract proven (CONTEXT.md discretion constraint: SARIF is the SINGLE finding
source; native JSON is enrichment ONLY):

    * build_osv_enrichment keys on (normalized_cve, normalized_pkg, version) and
      registers a vuln under EVERY id/alias (so a CVE-keyed SARIF finding matches
      even when the JSON native id is the GHSA/PYSEC);
    * the recorded urllib3/CVE-2025-66471 entry -> fixed_version == "2.6.0";
    * dependency_groups absent (flat requirements.txt) -> direct == None (A4
      honesty, never a fabricated False);
    * apply_enrichment writes direct/path_to_root/fixed_version into
      evidence.parsed_value and leaves an unmatched finding intact (direct=None);
    * COUNT INVARIANT: len(findings) is unchanged by enrichment.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sca.enrich import (
    apply_enrichment,
    build_osv_enrichment,
    enrichment_key_for,
    normalize_cve,
    normalize_pkg,
)
from repo_audit.schema.finding import Evidence, Finding

_JSON_FIXTURE = Path(__file__).parent / "fixtures" / "osv-scanner" / "sample.json"
_SARIF_FIXTURE = (
    Path(__file__).parent.parent
    / "sarif"
    / "fixtures"
    / "osv-scanner"
    / "sample.sarif"
)


@pytest.fixture
def osv_json() -> dict:
    return json.loads(_JSON_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def osv_findings() -> list[Finding]:
    sarif = json.loads(_SARIF_FIXTURE.read_text(encoding="utf-8"))
    return sarif_to_findings(
        sarif,
        source_tool="osv-scanner",
        default_dimension="security",
        severity_map={},
    )


# --- normalization helpers ------------------------------------------------


def test_normalize_cve_uppercases_and_strips():
    assert normalize_cve("  cve-2025-66471 ") == "CVE-2025-66471"
    assert normalize_cve("GHSA-2xpw-w6gg-jr37") == "GHSA-2XPW-W6GG-JR37"


def test_normalize_pkg_lowercases_and_strips_prefix():
    assert normalize_pkg("URLlib3") == "urllib3"
    assert normalize_pkg("pkg:pypi/urllib3") == "urllib3"
    assert normalize_pkg("pypi:urllib3") == "urllib3"
    assert normalize_pkg("pkg:pypi/urllib3@1.23.0") == "urllib3"


# --- build_osv_enrichment -------------------------------------------------


def test_build_enrichment_keys_on_cve_pkg_version(osv_json):
    enrichment = build_osv_enrichment(osv_json)
    key = (normalize_cve("CVE-2025-66471"), normalize_pkg("urllib3"), "1.23.0")
    assert key in enrichment


def test_build_enrichment_fix_version_for_recorded_cve(osv_json):
    enrichment = build_osv_enrichment(osv_json)
    key = (normalize_cve("CVE-2025-66471"), normalize_pkg("urllib3"), "1.23.0")
    assert enrichment[key]["fixed_version"] == "2.6.0"


def test_build_enrichment_direct_is_none_when_groups_absent(osv_json):
    """A4: dependency_groups null for flat requirements.txt -> direct UNKNOWN."""
    enrichment = build_osv_enrichment(osv_json)
    key = (normalize_cve("CVE-2025-66471"), normalize_pkg("urllib3"), "1.23.0")
    assert enrichment[key]["direct"] is None


def test_build_enrichment_indexes_under_aliases(osv_json):
    """A vuln whose native id is a GHSA is also reachable via its CVE alias."""
    enrichment = build_osv_enrichment(osv_json)
    # CVE-2019-11236's native id in JSON is PYSEC-2019-132; keyed under both.
    cve_key = (normalize_cve("CVE-2019-11236"), normalize_pkg("urllib3"), "1.23.0")
    pysec_key = (normalize_cve("PYSEC-2019-132"), normalize_pkg("urllib3"), "1.23.0")
    assert cve_key in enrichment
    assert pysec_key in enrichment


def test_build_enrichment_constructs_no_finding(osv_json):
    """Sanity: the map values are plain dicts, not Findings."""
    enrichment = build_osv_enrichment(osv_json)
    for payload in enrichment.values():
        assert isinstance(payload, dict)
        assert set(payload) == {"direct", "path_to_root", "fixed_version"}


# --- enrichment_key_for ---------------------------------------------------


def test_enrichment_key_for_matches_json_key(osv_json, osv_findings):
    """The key derived from the SARIF finding matches a JSON enrichment key."""
    enrichment = build_osv_enrichment(osv_json)
    f = osv_findings[0]
    key = enrichment_key_for(f)
    assert key == (normalize_cve("CVE-2025-66471"), normalize_pkg("urllib3"), "1.23.0")
    assert key in enrichment


# --- apply_enrichment -----------------------------------------------------


def test_apply_enrichment_writes_parsed_value(osv_json, osv_findings):
    enrichment = build_osv_enrichment(osv_json)
    apply_enrichment(osv_findings, enrichment)
    f = osv_findings[0]
    assert f.evidence.parsed_value["direct"] is None
    assert f.evidence.parsed_value["path_to_root"] == []
    assert f.evidence.parsed_value["fixed_version"] == "2.6.0"
    assert f.recommendation == "upgrade to 2.6.0"


def test_apply_enrichment_count_invariant(osv_json, osv_findings):
    """COUNT INVARIANT: enrichment never adds or removes a finding."""
    enrichment = build_osv_enrichment(osv_json)
    before = len(osv_findings)
    apply_enrichment(osv_findings, enrichment)
    after = len(osv_findings)
    assert after == before


def test_apply_enrichment_unmatched_finding_left_intact():
    """A finding with no enrichment entry -> direct=None, fixed=None, not dropped."""
    f = Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(
            tool="osv-scanner",
            output_snippet="Package 'leftpad@9.9.9' is vulnerable to 'CVE-9999-0001'.",
        ),
        evidence_type="static",
        confidence="candidate",
        source_tool="osv-scanner",
        rule_id="CVE-9999-0001",
    )
    findings = [f]
    apply_enrichment(findings, {})  # empty enrichment map
    assert len(findings) == 1
    assert findings[0].evidence.parsed_value["direct"] is None
    assert findings[0].evidence.parsed_value["fixed_version"] is None
    assert findings[0].evidence.parsed_value["path_to_root"] == []
