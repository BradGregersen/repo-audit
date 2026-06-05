"""VER-02 / SC2 — tiered corroboration promotes candidate→corroborated (RAISES only).

Wave 0 stub. De-xfailed and made real in Plan 17-01 Task 2 (this same plan, run
sequentially after the stub set lands).
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 1 (17-01 Task 2) implements tiered_corroborate", strict=False)
def test_tier_promotion_raises_only():
    """Tiered corroboration promotes candidate→corroborated; len unchanged, no deletion."""
    from repo_audit.verification.corroborate import tiered_corroborate  # noqa: F401

    raise AssertionError("tiered_corroborate not yet implemented")
