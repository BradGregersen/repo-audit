"""E2E lane package (E2E-01, Plan 16-02 — Task 1 surface).

Task 1 lands the tri-state detection + the ``e2e:`` config reader + the
``E2eScanResult`` envelope and a detection-only ``detect`` entry point. Task 2
expands this package with the full ``run_e2e`` run path (runners + parsers).

``E2eScanResult`` is copied VERBATIM from ``test_depth.TestDepthScanResult``
(renamed, ``__test__=False`` kept) — the never-raise tri-state envelope the scan
runner folds into the merged finding set + scope ledger.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.adapters.e2e.config import E2eConfig, read_e2e_config
from repo_audit.adapters.e2e.detect import detected_harnesses, harness_state
from repo_audit.schema.finding import Finding

# Tri-state (D-16-02): not_applicable = no harness; unavailable = harness present
# but not run (named precondition); ok/partial = ran; timeout = run timed out.
E2eStatus = Literal["ok", "partial", "unavailable", "timeout", "not_applicable"]


@dataclass
class E2eScanResult:
    """The never-raise envelope returned by the E2E lane (mirrors TestDepthScanResult).

    ``scan_runner`` reads ``findings`` into the merged finding set, ORs
    ``status != "ok"`` into the partial flag, and folds ``notes`` /
    ``ledger_notes`` into the scope ledger (SAFE-08 honest disclosure).
    """

    # Tell pytest NOT to collect this as a test class.
    __test__ = False

    findings: list[Finding] = field(default_factory=list)
    status: E2eStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)
    # Best-effort coverage percentage (D-16-03). None = unavailable / not invented.
    coverage_pct: float | None = None


def detect(repo_path: Path) -> E2eScanResult:
    """Tri-state detection entry point (D-16-02), WITHOUT running the harness.

    Resolves the *none vs present* legs into a result-bearing envelope:

      * no harness → ``status="not_applicable"``, note "no E2E configured".
      * harness present (but this entry never runs it) → ``status="unavailable"``
        with a note naming the detected harness + "detected, not run" so a
        configured-but-unrun harness is never conflated with "no E2E configured"
        (Pitfall 1).

    READ-ONLY, NEVER raises. The full opt-in run path is :func:`run_e2e`
    (Task 2).
    """
    harnesses = detected_harnesses(Path(repo_path))
    if not harnesses:
        return E2eScanResult(
            status="not_applicable",
            notes="no E2E configured (no Detox/Maestro/Playwright harness detected)",
            ledger_notes=["E2E not applicable: no E2E harness configured"],
        )
    names = ", ".join(harnesses)
    return E2eScanResult(
        status="unavailable",
        notes=(
            f"E2E harness detected ({names}) but not run — "
            "not opted in / infra unavailable"
        ),
        ledger_notes=[f"E2E harness present ({names}) — detected, not run"],
    )


__all__ = [
    "E2eScanResult",
    "E2eStatus",
    "detect",
    "harness_state",
    "detected_harnesses",
    "E2eConfig",
    "read_e2e_config",
]
