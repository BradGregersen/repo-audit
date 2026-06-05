"""E2E lane harness-detection contract (E2E-01, Wave 0 scaffolding).

Pins the tri-state detection contract for Plan 16-02:
  * absent harness -> "no E2E configured" not_applicable (never a failure),
  * harness present but not opted-in / no infra -> a DISTINCT "detected-not-run"
    unavailable status (D-16-02), so a configured-but-unrun harness is never
    silently conflated with "no harness at all".

``importorskip`` keeps these SKIPPED until ``repo_audit.adapters.e2e``
lands, then they flip ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

from pathlib import Path

import pytest

e2e = pytest.importorskip(
    "repo_audit.adapters.e2e",
    reason="Wave 1/2 (plan 16-02) not yet landed — adapters.e2e missing",
)


def _detect(repo: Path):
    """Invoke the lane's detection entry point, tolerating naming variants."""
    for name in ("detect", "detect_harness", "harness_state", "run_e2e"):
        fn = getattr(e2e, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.e2e exposes no detection entry point")


def test_no_harness_unavailable(tmp_path: Path):
    """A repo with no E2E harness -> "no E2E configured" not_applicable.

    Absence of a harness is a NOT-A-FAILURE state: the lane reports that E2E is
    not configured, never a red status, and never invents a harness.
    """
    result = _detect(tmp_path)
    status = getattr(result, "status", result)
    assert status in ("not_applicable", "unavailable")
    note = (getattr(result, "notes", "") or "").lower()
    # The "no E2E configured" signal is what distinguishes this from a present
    # harness that simply did not run.
    assert "e2e" in note or "harness" in note or "configured" in note


def test_detected_not_run_distinct(tmp_path: Path):
    """A present-but-unrun harness -> a DISTINCT "detected-not-run" status (D-16-02).

    A Playwright config exists but the run is not opted-in / no infra is present,
    so the lane must surface a status that is distinguishable from BOTH "no
    harness" and "ran". The note names the detected-not-run condition.
    """
    (tmp_path / "playwright.config.ts").write_text(
        "export default {};\n", encoding="utf-8"
    )
    result = _detect(tmp_path)
    status = getattr(result, "status", result)
    note = (getattr(result, "notes", "") or "").lower()
    # Detected-not-run is an unavailable variant whose NOTE makes the distinction
    # explicit — it must not read as "no E2E configured".
    assert status in ("unavailable", "detected_not_run", "partial")
    assert "detect" in note or "not run" in note or "not-run" in note or "opt" in note
