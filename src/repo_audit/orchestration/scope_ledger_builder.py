"""build_scope_ledger — assembles ScopeLedger from walker output + collector results.

Pattern 7 (RESEARCH.md): the ledger writes itself from collector returns
(D-30, D-22). No separate ledger-population pass.

Scanned subsection: one row per top-level walked dir; file_count is the
number of indexed files under that dir; collectors lists the
source_collector names that ran (Phase 2's universal collectors run on
every dir; Phase 3+ adapters may run per-dir).

Skipped subsection: one row per dir the walker pruned (DEFAULT_SKIP_DIRS
auto-logged in walker.repo_index).

Unavailable subsection: one row per non-ok CollectorResult; dimension +
collector + reason from the result's own self-report. Per D-25, errors
surface here — NOT as evidence_type='unavailable' meta-findings.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.scope_ledger import (
    ScannedEntry,
    ScopeLedger,
    SkippedEntry,
    UnavailableEntry,
)
from repo_audit.walker.repo_index import WalkerResult


def build_scope_ledger(
    walker_result: WalkerResult,
    collector_results: list[CollectorResult],
    *,
    repo_path: Path,
) -> ScopeLedger:
    """Assemble the ScopeLedger from walker output + per-collector status.

    Args:
        walker_result: output of build_repo_index(repo_path)
        collector_results: list of CollectorResult from run_collectors()
        repo_path: target repo root (used for relative-path conversion)

    Returns:
        ScopeLedger with scanned/skipped/unavailable + notes populated.
    """
    repo_path = Path(repo_path).resolve()

    # Scanned: one entry per top-level walked dir.
    # collectors = sorted unique source_collector strings from results
    # (Phase 2's universal posture — every collector runs on every dir).
    all_collectors = sorted({
        r.source_collector for r in collector_results if r.source_collector
    })
    scanned: list[ScannedEntry] = []
    for d in walker_result.scanned_dirs:
        try:
            rel = str(d.relative_to(repo_path))
        except ValueError:
            rel = str(d)
        file_count = sum(
            1 for p in walker_result.index.keys() if _is_under(p, d)
        )
        scanned.append(ScannedEntry(
            dir=rel,
            file_count=file_count,
            collectors=all_collectors,
        ))

    # Skipped: one entry per walker_result.skipped_dirs.
    skipped: list[SkippedEntry] = []
    for d, reason in walker_result.skipped_dirs:
        try:
            rel = str(d.relative_to(repo_path))
        except ValueError:
            rel = str(d)
        skipped.append(SkippedEntry(dir=rel, reason=reason))

    # Unavailable: one entry per non-ok CollectorResult.
    unavailable: list[UnavailableEntry] = []
    for r in collector_results:
        if r.status != "ok":
            unavailable.append(UnavailableEntry(
                dimension=r.dimension or "unknown",
                collector=r.source_collector or "unknown",
                reason=r.notes or r.status,
            ))

    return ScopeLedger(
        scanned=scanned,
        skipped=skipped,
        unavailable=unavailable,
        notes=walker_result.notes,
    )


def _is_under(path: Path, ancestor: Path) -> bool:
    """True iff path is the same as ancestor or lives under it."""
    try:
        path.relative_to(ancestor)
        return True
    except ValueError:
        return False
