"""VER-02 — positive reachability is an independent 2nd signal; negative/unknown
NEVER deletes/demotes (SAFE-01 downgrade-safe, D-17-03).

Wave 0 stub. De-xfailed and made real in Plan 17-01 Task 1 (this same plan).
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 1 (17-01 Task 1) implements check_reachable", strict=False)
def test_unreachable_never_drops():
    """A negative/unknown reachability result returns False/None and never deletes."""
    from repo_audit.verification.reachability import check_reachable  # noqa: F401

    raise AssertionError("check_reachable not yet implemented")
