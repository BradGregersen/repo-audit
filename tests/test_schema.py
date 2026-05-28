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
