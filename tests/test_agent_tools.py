"""Wave 0 stub for AGENT-01, D-54, D-58.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_tool_registry_shape                 (AGENT-01 — tool registry shape)
- test_tool_description_lifted_from_docstring (D-58 — @tool description from docstring)
- test_emit_report_tool_uses_pydantic_schema  (D-54 — emit_report uses pydantic schema)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.tools",
    reason="optional module repo_audit.agent.tools not importable — feature not present in this build, or the install is incomplete",
)


def test_tool_registry_shape():
    """AGENT-01: the tool registry has the expected shape.

    15 callables: 6 universal collector getters + 4 TS-adapter getters
    + 3 ledger/meta/dimension getters + 1 trend_baseline (Plan 05-03)
    + 1 emit_report.
    """
    assert len(_mod.ALL_TOOLS) == 15
    # Every entry is a registered @tool object with a `name` attribute.
    names = {getattr(t, "name", getattr(t, "__name__", "")) for t in _mod.ALL_TOOLS}
    assert "emit_report" in names
    assert "get_git_cadence_findings" in names
    assert "get_tsc_diagnostics" in names
    assert "trend_baseline" in names


def test_tool_description_lifted_from_docstring():
    """D-58: the @tool description is lifted from the module docstring.

    The tsc getter's description equals inspect.getdoc() of the tsc
    parser module (single source of truth — change the 'when to use'
    text in the collector module, the agent's view updates).
    """
    import inspect

    import repo_audit.adapters.typescript.parsers.tsc as tsc_mod

    expected = (inspect.getdoc(tsc_mod) or "").strip()
    desc = getattr(_mod.get_tsc_diagnostics, "description", None)
    assert desc == expected
    assert "When to use:" in desc and "When NOT to use:" in desc


def test_emit_report_tool_uses_pydantic_schema():
    """D-54: the emit_report tool uses the AgentScanReport pydantic schema.

    The registered input_schema carries `additionalProperties: False` —
    the marker that extra='forbid' produced the schema (T-04-05-01).
    """
    from repo_audit.agent.schema import AgentScanReport

    schema = getattr(_mod.emit_report, "input_schema", None)
    assert schema is not None
    assert schema.get("additionalProperties") is False
    # Cross-reference: it is the AgentScanReport-derived schema.
    assert schema == AgentScanReport.model_json_schema()
