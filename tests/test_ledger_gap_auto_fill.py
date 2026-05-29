"""AGENT-07, D-60 — post-flight ledger-gap auto-fill (Plan 04-09).

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Plan 04-09 supplies the real
bodies here (the Wave 0 stub used `pass` bodies to pin the contract names).

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

from repo_audit.orchestration.scope_ledger_builder import (  # noqa: E402
    UNIVERSAL_REQUIRED_COLLECTORS,
    auto_fill_ledger_gaps,
)
from repo_audit.schema.detection import DetectionResult  # noqa: E402
from repo_audit.schema.scope_ledger import ScopeLedger, UnavailableEntry  # noqa: E402


def _empty_detection() -> DetectionResult:
    """No stacks → only the 6 UNIVERSAL collectors are considered."""
    return DetectionResult(stacks=[])


def test_missing_required_collector_auto_filled(tmp_path):
    """AGENT-07/D-60: a missing required collector is auto-filled into the ledger.

    Start with findings + scope_ledger that omit `git_cadence` entirely (no
    finding sourced from it, no unavailable row naming it). After auto-fill,
    a git_cadence row exists somewhere: either a new finding sourced from it,
    or a synthesized scope_ledger.unavailable entry naming it.
    """
    findings: list = []
    scope_ledger = ScopeLedger()

    new_findings, new_ledger = auto_fill_ledger_gaps(
        findings,
        scope_ledger,
        _empty_detection(),
        repo_path=tmp_path,
        walker_index={},
    )

    git_cadence_finding = any(
        getattr(f, "source_collector", "") == "git_cadence" for f in new_findings
    )
    git_cadence_unavailable = any(
        getattr(u, "collector", "") == "git_cadence" for u in new_ledger.unavailable
    )
    assert git_cadence_finding or git_cadence_unavailable, (
        "git_cadence had no ledger row but auto-fill produced neither a "
        "finding nor an unavailable entry for it"
    )


def test_auto_fill_logs_to_notes(tmp_path):
    """D-60: the auto-fill action is logged to the ledger notes (verbatim text)."""
    findings: list = []
    scope_ledger = ScopeLedger()

    _new_findings, new_ledger = auto_fill_ledger_gaps(
        findings,
        scope_ledger,
        _empty_detection(),
        repo_path=tmp_path,
        walker_index={},
    )

    # At least one universal collector was missing → the D-60 note fires.
    assert "gap auto-filled:" in new_ledger.notes
    assert "had no row at post-flight check" in new_ledger.notes


def test_universal_required_collectors_iterated(tmp_path):
    """D-60: the function iterates ALL 6 UNIVERSAL_REQUIRED_COLLECTORS.

    With every universal collector missing, every one must be visited — the
    notes log must mention each universal collector name exactly.
    """
    assert len(UNIVERSAL_REQUIRED_COLLECTORS) == 6
    findings: list = []
    scope_ledger = ScopeLedger()

    _new_findings, new_ledger = auto_fill_ledger_gaps(
        findings,
        scope_ledger,
        _empty_detection(),
        repo_path=tmp_path,
        walker_index={},
    )

    for name in UNIVERSAL_REQUIRED_COLLECTORS:
        assert name in new_ledger.notes, (
            f"{name} was not iterated by auto_fill_ledger_gaps"
        )


def test_existing_row_is_not_refilled(tmp_path):
    """D-60: a collector that already has a row is NOT re-invoked / re-logged."""
    findings: list = []
    scope_ledger = ScopeLedger(
        unavailable=[
            UnavailableEntry(
                dimension="process",
                collector="git_cadence",
                reason="not a git repo",
            )
        ]
    )

    _new_findings, new_ledger = auto_fill_ledger_gaps(
        findings,
        scope_ledger,
        _empty_detection(),
        repo_path=tmp_path,
        walker_index={},
    )

    # git_cadence already had a row → no gap note for it.
    assert "gap auto-filled: git_cadence" not in new_ledger.notes
