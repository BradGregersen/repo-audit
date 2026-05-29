"""Wave 0 stub for AGENT-07, D-60.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_missing_required_collector_auto_filled (AGENT-07/D-60 — missing required collector auto-filled)
- test_auto_fill_logs_to_notes                (D-60 — auto-fill logs to notes)
- test_universal_required_collectors_iterated (D-60 — walks UNIVERSAL_REQUIRED_COLLECTORS)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.orchestration.scope_ledger_builder",
    reason="Wave 1+ plan 04-08 has not landed yet — Wave 0 stub.",
)


def test_missing_required_collector_auto_filled():
    """AGENT-07/D-60: a missing required collector is auto-filled into the ledger."""
    pass


def test_auto_fill_logs_to_notes():
    """D-60: the auto-fill action is logged to the ledger notes."""
    pass


def test_universal_required_collectors_iterated():
    """D-60: the builder walks UNIVERSAL_REQUIRED_COLLECTORS."""
    pass
