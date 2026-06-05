"""VER-03 — critic must cite file:line / lockfile / policy; an uncited refutation
is discarded (logged, no retry, zero effect).

Wave 0 stub. A later wave (Plan 17-02) implements the deterministic citation
validator.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 2 (17-02) implements the citation validator", strict=False)
def test_uncited_refutation_discarded_no_retry():
    """An uncited/invalid refutation is discarded with no retry and zero effect."""
    raise AssertionError("citation validator not yet implemented")
