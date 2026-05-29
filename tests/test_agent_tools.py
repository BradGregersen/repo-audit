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
    reason="Wave 1+ plan 04-04 has not landed yet — Wave 0 stub.",
)


def test_tool_registry_shape():
    """AGENT-01: the tool registry has the expected shape."""
    pass


def test_tool_description_lifted_from_docstring():
    """D-58: the @tool description is lifted from the function docstring."""
    pass


def test_emit_report_tool_uses_pydantic_schema():
    """D-54: the emit_report tool uses the pydantic schema."""
    pass
