"""Plan 08-02 Task 2 — splinter row→Finding mapper (deterministic, verify-phrased).

Drives ``splinter_collect.map_splinter_rows`` OFFLINE against the frozen
``splinter_rows_fixture`` (conftest) — no DB. splinter emits ROWS, not SARIF
(D-08-14): a 10-column uniform shape
(name,title,level,facing,categories,description,detail,remediation,metadata,
cache_key). The mapper turns each row into a ``Finding`` that is:

  * ``evidence_type="static"`` + ``confidence="candidate"`` (D-08-17),
  * deterministically severitied (level→Severity, ERROR capped at ``major``
    because SCH-04 forbids candidate+critical/blocker; faithful severity stashed
    in evidence.parsed_value),
  * deterministically dimensioned (categories→Dimension),
  * verify-phrased (no enforced/secure/protected) — proven by routing every
    mapped batch through ``assert_verify_phrasing`` without a raise (CRIT-4).

The two RLS-04 splinter-native footguns (``security_definer_view``,
``rls_references_user_metadata``) must map to ``dimension="security"`` findings.
"""
from __future__ import annotations

import pytest

from repo_audit.adapters.supabase.splinter_collect import (
    _CATEGORY_TO_DIMENSION,
    _LEVEL_TO_SEVERITY,
    map_splinter_rows,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_one_finding_per_row_all_static_candidate(splinter_rows_fixture):
    findings = map_splinter_rows(splinter_rows_fixture)
    assert len(findings) == len(splinter_rows_fixture)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    assert all(f.source_tool == "splinter" for f in findings)


def test_rule_id_is_splinter_name(splinter_rows_fixture):
    findings = map_splinter_rows(splinter_rows_fixture)
    rule_ids = {f.rule_id for f in findings}
    assert "rls_disabled_in_public" in rule_ids
    assert "security_definer_view" in rule_ids
    assert "rls_references_user_metadata" in rule_ids


def test_level_to_severity_table():
    """ERROR→major (NOT critical/blocker — SCH-04 cap), WARN→minor, INFO→info."""
    assert _LEVEL_TO_SEVERITY["ERROR"] == "major"
    assert _LEVEL_TO_SEVERITY["WARN"] == "minor"
    assert _LEVEL_TO_SEVERITY["INFO"] == "info"


def test_error_maps_to_major_never_critical(splinter_rows_fixture):
    findings = _by_rule(map_splinter_rows(splinter_rows_fixture))
    # rls_disabled_in_public is an ERROR row.
    f = findings["rls_disabled_in_public"]
    assert f.severity == "major"
    assert f.severity not in {"critical", "blocker"}


def test_warn_performance_row_maps_minor_quality(splinter_rows_fixture):
    findings = _by_rule(map_splinter_rows(splinter_rows_fixture))
    # auth_rls_initplan is WARN / PERFORMANCE.
    f = findings["auth_rls_initplan"]
    assert f.severity == "minor"
    assert f.dimension == "quality"


def test_category_to_dimension_table():
    assert _CATEGORY_TO_DIMENSION["SECURITY"] == "security"
    assert _CATEGORY_TO_DIMENSION["PERFORMANCE"] == "quality"


def test_security_footguns_map_to_security_dimension(splinter_rows_fixture):
    """RLS-04 native coverage: the two footgun rows are security findings."""
    findings = _by_rule(map_splinter_rows(splinter_rows_fixture))
    assert findings["security_definer_view"].dimension == "security"
    assert findings["rls_references_user_metadata"].dimension == "security"


def test_faithful_severity_preserved_for_capped_error(splinter_rows_fixture):
    """ERROR caps at major but the faithful (would-be-higher) severity is stashed."""
    findings = _by_rule(map_splinter_rows(splinter_rows_fixture))
    f = findings["rls_disabled_in_public"]
    pv = f.evidence.parsed_value
    assert pv.get("faithful_severity") == "critical"
    # The raw 10-col row is preserved for provenance.
    assert pv.get("name") == "rls_disabled_in_public"
    assert pv.get("level") == "ERROR"
    assert "categories" in pv


def test_warn_row_has_no_faithful_severity_uplift(splinter_rows_fixture):
    """WARN is not capped — faithful_severity equals the mapped severity (or absent)."""
    findings = _by_rule(map_splinter_rows(splinter_rows_fixture))
    f = findings["auth_rls_initplan"]
    fs = f.evidence.parsed_value.get("faithful_severity")
    # Either omitted or equal to the mapped severity — never a downgrade claim.
    assert fs in (None, "minor")


def test_messages_are_verify_phrased(splinter_rows_fixture):
    """No enforced/secure/protected; passes the shared CRIT-4 tripwire."""
    findings = map_splinter_rows(splinter_rows_fixture)
    banned = ("enforced", "secure", "protected")
    for f in findings:
        surface = " ".join(
            [
                f.recommendation or "",
                f.confidence_caveat or "",
                f.evidence.output_snippet or "",
            ]
        ).lower()
        for word in banned:
            assert word not in surface, f"{f.rule_id} prose carries {word!r}"
    # And the canonical guard does not raise.
    assert_verify_phrasing(findings)


def test_mapper_routes_through_tripwire_internally(splinter_rows_fixture):
    """map_splinter_rows itself returns only tripwire-clean findings."""
    # If the mapper did NOT call assert_verify_phrasing it would still pass the
    # external check above; this test pins that a violation in source detail does
    # not leak through by constructing a hostile row.
    hostile = dict(splinter_rows_fixture[0])
    hostile["detail"] = "This table is fully secure and enforced."
    # The mapper must NOT echo raw detail into report prose verbatim; the
    # rendered message is verify-phrased, so the tripwire stays clean.
    findings = map_splinter_rows([hostile])
    assert_verify_phrasing(findings)  # must not raise
