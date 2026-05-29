"""Wave 0 stub for AGENT-06, D-65, D-67.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names. The renderer module exists today, but the footer-rendering
symbols this file binds against land in a later Wave; the importorskip gate
on the renderer module keeps the contract pinned without depending on the
exact symbol existing yet (the Wave N test bodies assert the symbols).

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_footer_shows_cost_and_duration       (AGENT-06 — footer shows cost + duration)
- test_footer_shows_token_usage             (AGENT-06/D-65 — footer shows token usage)
- test_footer_shows_agent_status_when_unavailable (D-67 — footer shows agent status when unavailable)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.renderer",
    reason="Wave 1+ (footer-rendering symbols) has not landed yet — Wave 0 stub.",
)


def test_footer_shows_cost_and_duration():
    """AGENT-06: the report footer shows agent cost and duration."""
    pass


def test_footer_shows_token_usage():
    """AGENT-06/D-65: the report footer shows token usage."""
    pass


def test_footer_shows_agent_status_when_unavailable():
    """D-67: the footer shows the agent status when unavailable."""
    pass
