"""Wave 0 stub for AGENT-01, AGENT-05, AGENT-06, D-55, D-65, D-67, D-68.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_single_client_loop          (AGENT-01 — one ClaudeSDKClient drives the loop)
- test_token_budget_cap            (AGENT-05, D-65 — token budget cap honored)
- test_max_budget_usd_signal       (AGENT-05, D-65 — ResultMessage.subtype=='error_max_budget_usd')
- test_meta_cost_capture           (AGENT-06 — total_cost_usd captured into meta)
- test_auth_missing_fallback       (D-67 — CLINotFoundError → unavailable_auth_missing)
- test_network_fallback_after_retry(D-67/D-68 — outer retry then unavailable_network)
- test_repair_loop_exhausted       (D-55/D-67 — → unavailable_emit_report_invalid)
- test_write_attempt_blocked       (AGENT-03 — mocked-SDK behavior assertion)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.session",
    reason="Wave 1+ plan 04-05 has not landed yet — Wave 0 stub.",
)


def test_single_client_loop():
    """AGENT-01: a single ClaudeSDKClient drives the agent loop."""
    pass


def test_token_budget_cap():
    """AGENT-05, D-65: the token budget cap is honored."""
    pass


def test_max_budget_usd_signal():
    """AGENT-05, D-65: ResultMessage.subtype=='error_max_budget_usd' handled."""
    pass


def test_meta_cost_capture():
    """AGENT-06: total_cost_usd is captured into report meta."""
    pass


def test_auth_missing_fallback():
    """D-67: CLINotFoundError → unavailable_auth_missing fallback."""
    pass


def test_network_fallback_after_retry():
    """D-67/D-68: outer retry then unavailable_network fallback."""
    pass


def test_repair_loop_exhausted():
    """D-55/D-67: repair loop exhausted → unavailable_emit_report_invalid."""
    pass


def test_write_attempt_blocked():
    """AGENT-03: a write attempt is blocked (mocked-SDK behavior assertion)."""
    pass
