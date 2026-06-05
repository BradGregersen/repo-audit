"""VER-03 / SC3 — critic runs under its OWN token + wall-clock budget; honest
partial on exhaustion (CRIT-5).

Wave 0 stub. A later wave (Plan 17-02) implements the critic session + budget.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 2 (17-02) implements the critic budget", strict=False)
def test_budget_exhaustion_honest_partial():
    """On budget exhaustion the critic stops and discloses N-of-M honestly."""
    raise AssertionError("critic budget not yet implemented")
