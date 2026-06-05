"""VER-04 — a validly-refuted finding leaves the active set, lands in the Refuted
appendix WITH reason+citation, confidence dropped — never silently vanishes.

Wave 0 stub. A later wave (Plan 17-03) implements the refuted appendix.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 3 (17-03) implements the refuted appendix", strict=False)
def test_valid_refutation_to_appendix_not_vanished():
    """A validly-refuted finding lands in the appendix with reason+citation."""
    raise AssertionError("refuted appendix not yet implemented")
