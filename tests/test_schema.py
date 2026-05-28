"""Schema contract tests. Implementation lands in Plan 02 (Wave 1)."""
import pytest


def test_critical_static_requires_caveat():
    """SC-4a / SCH-03 / SAFE-01 / D-17 — critical+static without caveat raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="security",
            severity="critical",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="static",
            confidence="high",
            confidence_caveat=None,
        )


def test_finding_forbids_secret_value_field():
    """SC-4b / SCH-08 — Finding has no `value`/`secret`/`match`/`raw` field; extra='forbid'."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding
    # 1) Construction with unknown field raises
    with pytest.raises(ValidationError):
        Finding(value="AKIA...EXAMPLE", dimension="security", severity="info", evidence_type="heuristic", confidence="candidate")
    # 2) Field absence: no field named value/secret/match/raw
    forbidden_names = {"value", "secret", "match", "raw"}
    assert not (forbidden_names & set(Finding.model_fields.keys()))


def test_dimension_literal():
    """SCH-02 — invalid dimension raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="not_a_dim",  # type: ignore[arg-type]
            severity="info",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="heuristic",
            confidence="candidate",
        )


def test_severity_literal():
    """SCH-05 — invalid severity raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="security",
            severity="catastrophic",  # type: ignore[arg-type]
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="heuristic",
            confidence="candidate",
        )


def test_evidence_type_literal():
    """SCH-03 — invalid evidence_type raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="security",
            severity="info",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="dynamic",  # type: ignore[arg-type]
            confidence="candidate",
        )


def test_confidence_literal():
    """SCH-04 — invalid confidence raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="security",
            severity="info",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="heuristic",
            confidence="probably",  # type: ignore[arg-type]
        )


def test_extra_forbidden():
    """SCH-01 / D-03 — Finding rejects unknown fields via extra='forbid'."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="security",
            severity="info",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={}, line_range=None),
            evidence_type="heuristic",
            confidence="candidate",
            some_extra_field="boom",
        )


def test_presence_only_severity_ceiling():
    """SAFE-03 / D-19 — parsed_value.presence_only=True requires severity='info'."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            dimension="quality",
            severity="major",
            evidence=Evidence(tool="x", output_snippet="", parsed_value={"presence_only": True}, line_range=None),
            evidence_type="heuristic",
            confidence="candidate",
        )


def test_output_snippet_capped_at_2048():
    """D-02 — output_snippet capped at 2048 chars with `… [+N chars truncated]` marker.

    The truncated count is computed from the OUTPUT_SNIPPET_CAP constant so
    the test does not couple to any specific input length. Future input-size
    changes will not break this test for the wrong reason.
    """
    from repo_audit.schema.finding import Evidence, OUTPUT_SNIPPET_CAP
    long = "x" * (OUTPUT_SNIPPET_CAP + 500)  # any size > cap; the surplus is what gets truncated
    e = Evidence(tool="t", output_snippet=long, parsed_value={}, line_range=None)
    expected_truncated = len(long) - OUTPUT_SNIPPET_CAP
    expected_marker = f"… [+{expected_truncated} chars truncated]"
    assert len(e.output_snippet) <= OUTPUT_SNIPPET_CAP + len(expected_marker)
    assert expected_marker in e.output_snippet


def test_schema_version_literal():
    """SCH-07 / D-21 — ScanReport.schema_version is Literal["1"]; other values raise."""
    from pydantic import ValidationError
    from repo_audit.schema.report import ScanReport, ReportMeta
    with pytest.raises(ValidationError):
        ScanReport(schema_version="2", meta=ReportMeta(repo_slug="x", commit_sha="abc", scan_date="2026-05-28", tool_version="0.1.0"))


# --- SCH-04 WIDENED rung-cap validator tests (Plan 03-01a, Decision B / D-51') ---
#
# The widened rule REJECTS confidence='candidate' + severity in {critical, blocker}
# ONLY. major/minor/info are PERMITTED at candidate confidence. The widening is
# deliberate so that the Phase 2 secret-detection finding (severity='major',
# confidence='candidate') stays valid without per-collector patches.


def test_candidate_severity_critical_rejected():
    """SCH-04 D-51' widened — confidence='candidate' + severity='critical' raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError, match="SCH-04"):
        Finding(
            dimension="security",
            severity="critical",
            evidence=Evidence(tool="x"),
            evidence_type="static",
            confidence="candidate",
            confidence_caveat="runtime not verified",  # satisfies SAFE-01 so we test SCH-04 in isolation
        )


def test_candidate_severity_blocker_rejected():
    """SCH-04 D-51' widened — confidence='candidate' + severity='blocker' raises ValidationError."""
    from pydantic import ValidationError
    from repo_audit.schema.finding import Finding, Evidence
    with pytest.raises(ValidationError, match="SCH-04"):
        Finding(
            dimension="security",
            severity="blocker",
            evidence=Evidence(tool="x"),
            evidence_type="heuristic",
            confidence="candidate",
        )


def test_candidate_severity_major_ALLOWED():
    """SCH-04 D-51' widened — confidence='candidate' + severity='major' is PERMITTED.

    Load-bearing test for the widened rule: this combination is what the Phase 2
    secret_detection collector emits (SAFE-06). Decision B explicitly preserves
    that finding without modifying the collector; the schema MUST permit this.
    """
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="x"),
        evidence_type="heuristic",
        confidence="candidate",
    )
    assert f.severity == "major"
    assert f.confidence == "candidate"


def test_candidate_severity_minor_allowed():
    """SCH-04 D-51' widened — confidence='candidate' + severity='minor' is PERMITTED."""
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="quality",
        severity="minor",
        evidence=Evidence(tool="x"),
        evidence_type="heuristic",
        confidence="candidate",
    )
    assert f.severity == "minor"


def test_candidate_severity_info_allowed():
    """SCH-04 D-51' widened — confidence='candidate' + severity='info' is PERMITTED."""
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="quality",
        severity="info",
        evidence=Evidence(tool="x"),
        evidence_type="heuristic",
        confidence="candidate",
    )
    assert f.severity == "info"


def test_corroborated_severity_critical_allowed():
    """SCH-04 D-51' — the rung-cap fires ONLY at candidate; corroborated+critical is fine."""
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="security",
        severity="critical",
        evidence=Evidence(tool="x"),
        evidence_type="static",
        confidence="corroborated",
        confidence_caveat="runtime not verified",  # SAFE-01
    )
    assert f.severity == "critical"
    assert f.confidence == "corroborated"


# --- EvidenceType 'failed' variant tests (Plan 03-01a, Decision C) ---
#
# The 5th EvidenceType variant is consumed by plan 03-03's _refresh_failed_finding
# helper and plan 03-05's CLI failure-synthesis path. SCH-03 critical+static caveat
# (D-17) MUST NOT trigger for evidence_type='failed' since 'failed' != 'static'.


def test_evidence_type_literal_includes_failed_variant():
    """Decision C structural pin — EvidenceType Literal contains 'failed'.

    Guards against a future regression that removes the 5th variant.
    """
    from typing import get_args
    from repo_audit.schema.enums import EvidenceType
    assert "failed" in get_args(EvidenceType), (
        f"EvidenceType must include 'failed' (Decision C); got {get_args(EvidenceType)}"
    )


def test_failed_evidence_type_constructs_cleanly():
    """Decision C — plan 03-03 _refresh_failed_finding helper shape validates clean.

    Representative of the lcov refresh-failure path: coverage_refresh emits a
    Finding with evidence_type='failed' when the runner produced no usable result.
    Neither SCH-03 (D-17 critical+static) nor SCH-04 widened (D-51') should reject
    this combination.
    """
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="test_integrity",
        severity="major",
        confidence="medium",
        evidence_type="failed",
        source_tool="coverage_refresh",
        source_collector="lcov",
        rule_id="coverage_refresh_failed",
        recommendation="Re-run the coverage refresh.",
        evidence=Evidence(tool="lcov-parser"),
    )
    assert f.evidence_type == "failed"
    assert f.severity == "major"


def test_failed_evidence_type_not_subject_to_critical_static_caveat():
    """Decision C — SCH-03 (D-17) critical+static caveat does NOT trigger for 'failed'.

    SCH-03 fires only when severity=='critical' AND evidence_type=='static'. Since
    'failed' != 'static', no confidence_caveat is required even at severity='critical'.
    Guard against a future schema change that accidentally widens SCH-03's trigger.
    """
    from repo_audit.schema.finding import Finding, Evidence
    f = Finding(
        dimension="test_integrity",
        severity="critical",
        confidence="medium",
        evidence_type="failed",
        source_tool="coverage_refresh",
        source_collector="lcov",
        rule_id="coverage_refresh_failed_critical",
        recommendation="Re-run the coverage refresh; surface as a blocking failure.",
        evidence=Evidence(tool="lcov-parser"),
        # NO confidence_caveat — proves SCH-03 doesn't fire for evidence_type='failed'.
    )
    assert f.evidence_type == "failed"
    assert f.severity == "critical"
    assert f.confidence_caveat is None
