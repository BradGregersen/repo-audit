"""CRIT-5 — "N of M findings critically reviewed" disclosed in the report; no
silent cap.

Wave 0 stub. A later wave (Plan 17-02/17-03) implements the partial-disclosure
meta + render.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 2/3 implements the N-of-M disclosure", strict=False)
def test_n_of_m_disclosed():
    """The report discloses how many of M findings were critically reviewed."""
    raise AssertionError("N-of-M disclosure not yet implemented")
