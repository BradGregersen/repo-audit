"""auto_fill_ledger_gaps must NOT invent unknown-dimension rows (Plan 12-05, Task 2).

Folded Pitfall 7 (kept ISOLATED): ``_adapter_required_collectors`` walks each
detected adapter's ``adapter.yaml.required_collectors`` — for typescript-node that
is ``[tsc, eslint, knip, coverage_lcov]``. Those are ADAPTER TOOL names, not
universal collector modules: ``_invoke_collector_by_name`` cannot locate them in
the COLLECTOR registry, so the pre-fix code appended a bogus
``UnavailableEntry(dimension="unknown", collector="tsc", ...)`` (and one for
coverage_lcov) whenever the adapter ran but emitted no finding / no unavailable row
for that specific tool (e.g. tsc found zero type errors → no finding, status ok →
no unavailable row).

After the fix, folding a typescript-node detection through ``auto_fill_ledger_gaps``
produces NO ``unknown``-dimension row for tsc / coverage_lcov.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.orchestration.scope_ledger_builder import auto_fill_ledger_gaps
from repo_audit.schema.detection import DetectionResult, StackProfile
from repo_audit.schema.scope_ledger import ScopeLedger


def _ts_detection(tmp_path) -> DetectionResult:
    return DetectionResult(
        stacks=[
            StackProfile(
                stack="typescript-node",
                root_dir=tmp_path,
                manifests=[tmp_path / "package.json"],
            )
        ]
    )


def test_no_unknown_dimension_row_for_adapter_tools(tmp_path):
    """A typescript-node adapter result folds with NO unknown-dimension row."""
    findings: list = []
    ledger = ScopeLedger()

    new_findings, new_ledger = auto_fill_ledger_gaps(
        findings,
        ledger,
        _ts_detection(tmp_path),
        repo_path=tmp_path,
        walker_index={},
    )

    # The bug: tsc / coverage_lcov (and eslint / knip) — adapter tool names not in
    # the COLLECTOR registry — would yield dimension="unknown" rows. They must not.
    unknown_rows = [
        u for u in new_ledger.unavailable if getattr(u, "dimension", "") == "unknown"
    ]
    bogus = [
        u for u in unknown_rows
        if getattr(u, "collector", "") in {"tsc", "coverage_lcov", "eslint", "knip"}
    ]
    assert not bogus, (
        f"auto_fill_ledger_gaps invented unknown-dimension rows for adapter "
        f"tools: {[(u.collector, u.reason) for u in bogus]}"
    )


def test_universal_collector_gaps_still_filled(tmp_path):
    """The fix is ISOLATED: genuine universal-collector gaps still get a row.

    A universal collector (e.g. git_cadence) with no finding / no unavailable row
    must still be auto-filled — the fix only suppresses the adapter-tool unknown
    rows, it does not disable the universal-collector gap mechanism.
    """
    findings: list = []
    ledger = ScopeLedger()

    _, new_ledger = auto_fill_ledger_gaps(
        findings,
        ledger,
        DetectionResult(stacks=[]),  # no adapters → only universal collectors
        repo_path=tmp_path,
        walker_index={},
    )

    # auto-fill ran for the universal collectors (notes recorded) — the mechanism
    # is intact. (On a tmp_path with no real git, the collectors degrade to
    # unavailable rows or get located + run; either way the universal names are
    # PROCESSED, not silently skipped like the adapter tools.)
    assert "gap auto-filled" in (new_ledger.notes or "")
