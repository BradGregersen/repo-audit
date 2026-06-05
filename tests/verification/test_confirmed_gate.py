"""VER-04 / SC4 — confirmed = corroborated AND critic-survived; no-critic-run
stays corroborated; runtime findings confirm without a critic run.

Wave 0 stub. A later wave (Plan 17-03) implements the confirmed gate.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 3 (17-03) implements the confirmed gate", strict=False)
def test_confirmed_requires_corrob_and_survival():
    """A finding is confirmed only if already corroborated AND critic-survived."""
    raise AssertionError("confirmed gate not yet implemented")


@pytest.mark.xfail(reason="Wave 3 (17-03) implements the confirmed gate", strict=False)
def test_runtime_finding_confirms_without_critic_run():
    """An evidence_type=='runtime' finding is confirm-eligible without a critic run."""
    raise AssertionError("confirmed gate not yet implemented")
