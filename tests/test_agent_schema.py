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

_mod = pytest.importorskip(
    "repo_audit.agent.schema",
    reason="Wave 1+ plan 04-02 has not landed yet — Wave 0 stub.",
)


def test_agent_scan_report_extra_forbid():
    """D-03/D-54: AgentScanReport rejects extra fields (extra='forbid')."""
    pass


def test_dimension_narrative_required_fields():
    """D-54: DimensionNarrative declares its required fields."""
    pass


def test_severity_call_required_fields():
    """D-54: SeverityCall declares its required fields."""
    pass


def test_no_markdown_in_agent_payload():
    """AGENT-04: the model has zero string fields named markdown/md/html."""
    pass


def test_faithfulness_violation_shape():
    """D-64: the faithfulness-violation record has the expected shape."""
    pass
