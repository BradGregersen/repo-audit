"""Wave 0 stub for AGENT-04, D-03, D-54, D-64.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_agent_scan_report_extra_forbid    (D-03/D-54 — AgentScanReport extra='forbid')
- test_dimension_narrative_required_fields(D-54 — DimensionNarrative required fields)
- test_severity_call_required_fields      (D-54 — SeverityCall required fields)
- test_no_markdown_in_agent_payload       (AGENT-04 — zero markdown/md/html string fields)
- test_faithfulness_violation_shape       (D-64 — FaithfulnessViolation shape)
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

_mod = pytest.importorskip(
    "repo_audit.agent.schema",
    reason="optional module repo_audit.agent.schema not importable — feature not present in this build, or the install is incomplete",
)

AgentScanReport = _mod.AgentScanReport
DimensionNarrative = _mod.DimensionNarrative
SeverityCall = _mod.SeverityCall
FaithfulnessViolation = _mod.FaithfulnessViolation


def test_agent_scan_report_extra_forbid():
    """D-03/D-54: AgentScanReport rejects extra fields (extra='forbid')."""
    # Valid payload constructs.
    AgentScanReport.model_validate(
        {"dimensions": [], "executive_summary": "x", "cross_cutting_notes": None}
    )
    # Smuggled extra field raises.
    with pytest.raises(ValidationError):
        AgentScanReport.model_validate(
            {
                "dimensions": [],
                "executive_summary": "x",
                "cross_cutting_notes": None,
                "extra_field": "bad",
            }
        )


def test_dimension_narrative_required_fields():
    """D-54: DimensionNarrative declares its required fields."""
    dn = DimensionNarrative(dimension="quality", narrative="...", severity_calls=[])
    assert dn.dimension == "quality"
    assert dn.narrative == "..."
    # Missing `narrative` raises.
    with pytest.raises(ValidationError):
        DimensionNarrative(dimension="quality", severity_calls=[])


def test_severity_call_required_fields():
    """D-54: SeverityCall declares its required fields."""
    sc = SeverityCall(
        finding_ref="eslint::no-eval::src/foo.ts:12",
        agent_severity="critical",
        corroborated_by=[],
    )
    assert sc.agent_severity == "critical"
    # An invalid Severity literal raises.
    with pytest.raises(ValidationError):
        SeverityCall(
            finding_ref="eslint::no-eval::src/foo.ts:12",
            agent_severity="kritisch",
            corroborated_by=[],
        )


def test_no_markdown_in_agent_payload():
    """AGENT-04: the model has zero string fields named markdown/md/html."""
    forbidden = {"markdown", "md", "html"}
    for model in (AgentScanReport, DimensionNarrative, SeverityCall):
        assert forbidden.isdisjoint(model.model_fields.keys()), (
            f"{model.__name__} must not declare a markdown-shaped field"
        )


def test_faithfulness_violation_shape():
    """D-64: the faithfulness-violation record has the expected shape."""
    fv = FaithfulnessViolation(
        original_sentence="...",
        offending_tokens=["73"],
        dimension="test_integrity",
        paragraph_index=0,
        nearest_allowed=73.4,
    )
    assert fv.offending_tokens == ["73"]
    assert fv.paragraph_index == 0
    assert fv.nearest_allowed == 73.4
    assert FaithfulnessViolation.model_config["extra"] == "forbid"


def test_agent_scan_report_json_schema_shape():
    """D-54: model_json_schema() exposes object/properties/dimensions $ref.

    Plan 04-05 registers this as the emit_report @tool input_schema; the SDK
    validates agent calls against it before invoking our handler.
    """
    schema = AgentScanReport.model_json_schema()
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "dimensions" in schema["properties"]
    dims = schema["properties"]["dimensions"]
    # dimensions is an array whose items $ref DimensionNarrative.
    assert dims.get("type") == "array"
    items = dims.get("items", {})
    assert "$ref" in items and "DimensionNarrative" in items["$ref"]
