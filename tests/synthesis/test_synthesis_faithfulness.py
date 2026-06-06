"""SYN-02 — `why_it_matters` citing the composite/driver survives the faithfulness
gate; an invented number is still stripped (negative control).

Clones the `tests/.../test_trend_faithfulness.py` AllowedNumbers-fold pattern.
Targets the Wave-2 synthesis faithfulness fold, not built in plan 18-01.
`importorskip` until the synthesis narration fold lands.
"""
from __future__ import annotations

import pytest

_faith = pytest.importorskip(
    "repo_audit.synthesis.faithfulness",
    reason="Wave 2 synthesis.faithfulness not yet implemented (plan 18-02+)",
)


def test_composite_folded_invented_stripped():
    # A narration citing the real composite/driver survives; an invented number
    # not in the AllowedNumbers set is stripped (negative control).
    allowed = _faith.allowed_numbers_for_score(composite=0.42, epss=0.9)  # pragma: no cover
    assert 0.42 in allowed
    cleaned = _faith.strip_unfaithful_numbers(
        "composite 0.42 with EPSS 0.9 but invented 99.99", allowed
    )
    assert "0.42" in cleaned
    assert "99.99" not in cleaned
