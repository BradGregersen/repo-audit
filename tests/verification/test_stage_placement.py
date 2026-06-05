"""VER-01 / SC1 — a verification stage runs in scan_runner.run_scan BETWEEN the
findings merge and run_agent_session, separate from the render chokepoint.

Wave 0 stub. NAME canonicalized to test_stage_placement.py (NOT
test_stage_insertion.py) per 17-VALIDATION.md. A later wave (Plan 17-03) wires
the stage into the scan pipeline.
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Wave 3 (17-03) wires the verification stage", strict=False)
def test_runs_before_narrator_after_merge():
    """The verification stage runs after the findings merge and before the narrator."""
    raise AssertionError("verification stage placement not yet wired")
