"""VER-05 / SC5 — downgrade-only post-pass: the critic may lower severity/confidence
but NEVER promotes static/heuristic → runtime/exploitable; runtime is born-runtime
only (SAFE-01, D-17-16).

Wave 0 stub. A later wave (Plan 17-03) implements the downgrade-only post-pass.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 3 (17-03) implements the downgrade-only post-pass", strict=False)
def test_no_static_to_runtime_promotion():
    """No finding gains evidence_type=='runtime' it was not born with."""
    raise AssertionError("downgrade-only post-pass not yet implemented")
