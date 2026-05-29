"""Wave 0 stub for AGENT-02, AGENT-03, D-59.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_allowed_tools_filters_by_stack (AGENT-02, D-59 — allowed_tools filtered by stack)
- test_no_writebash_in_options        (AGENT-03 — tools=[] AND no Write/Bash/Read in allowed_tools)
- test_tools_empty_list_is_explicit   (AGENT-03 — options.tools == [] not None, RESEARCH Pitfall 2)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.options",
    reason="Wave 1+ plan 04-04 has not landed yet — Wave 0 stub.",
)


def test_allowed_tools_filters_by_stack():
    """AGENT-02, D-59: allowed_tools is filtered by detected stack."""
    pass


def test_no_writebash_in_options():
    """AGENT-03: tools=[] AND no Write/Bash/Read in allowed_tools."""
    pass


def test_tools_empty_list_is_explicit():
    """AGENT-03 (RESEARCH Pitfall 2): options.tools == [] not None."""
    pass
