"""Wave 0 stub for D-55.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_repair_first_attempt_succeeds_no_retry  (D-55 — first attempt valid → no retry)
- test_repair_validates_after_one_retry        (D-55 — validates after one retry)
- test_repair_exhausted_after_three_attempts   (D-55 — 3 attempts → fall through to D-67)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.session",
    reason="Wave 1+ plan 04-05 has not landed yet — Wave 0 stub.",
)


def test_repair_first_attempt_succeeds_no_retry():
    """D-55: a valid first attempt incurs no retry."""
    pass


def test_repair_validates_after_one_retry():
    """D-55: the report validates after exactly one retry."""
    pass


def test_repair_exhausted_after_three_attempts():
    """D-55: total 3 attempts exhausted → fall through to D-67."""
    pass
