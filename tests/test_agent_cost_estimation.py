"""Wave 0 stub for D-65 (Claude's Discretion).

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_model_usd_per_mtok_table_exists (D-65 — model→USD/Mtok pricing table exists)
- test_unknown_model_returns_none      (RESEARCH Pitfall 8 — unknown model → None, fall back to total_cost_usd)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.cost_estimation",
    reason="Wave 1+ plan 04-05 has not landed yet — Wave 0 stub.",
)


def test_model_usd_per_mtok_table_exists():
    """D-65: the model→USD/Mtok pricing table exists."""
    pass


def test_unknown_model_returns_none():
    """RESEARCH Pitfall 8: an unknown model returns None (fall back to total_cost_usd)."""
    pass
