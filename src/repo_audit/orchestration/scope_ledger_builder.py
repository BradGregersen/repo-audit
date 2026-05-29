"""build_scope_ledger — assembles ScopeLedger from walker + collector + adapter results.

Pattern 7 (RESEARCH.md): the ledger writes itself from collector returns
(D-30, D-22). No separate ledger-population pass.

Scanned subsection: one row per top-level walked dir; file_count is the
number of indexed files under that dir; collectors lists the
source_collector names that ran (Phase 2's universal collectors run on
every dir) UNION the per-tool adapter labels (Phase 3+; each
AdapterResult contributes one ``"{source_adapter}:{source_tool}"`` entry).

Skipped subsection: one row per dir the walker pruned (DEFAULT_SKIP_DIRS
auto-logged in walker.repo_index).

Unavailable subsection:
    - One row per non-ok CollectorResult (dimension + collector + reason
      from the result's own self-report; per D-25, errors surface here —
      NOT as evidence_type='unavailable' meta-findings).
    - PLUS one row per non-ok AdapterResult (Phase 3+) using
      ``"{source_adapter}:{source_tool}"`` as the collector identifier so
      the report distinguishes "which adapter's which tool" cleanly.

Phase 3 extension contract (Plan 03-05):
    - ``adapter_results`` is a kwarg-only optional parameter; default
      ``None`` is treated as ``[]`` so every Phase 2 callsite that did NOT
      pass it continues to work without modification.
    - The kwarg-only positioning (after ``repo_path``) prevents accidental
      positional binding from old call patterns.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.scope_ledger import (
    ScannedEntry,
    ScopeLedger,
    SkippedEntry,
    UnavailableEntry,
)
from repo_audit.walker.repo_index import WalkerResult


def _adapter_label(ar: AdapterResult) -> str:
    """Return ``'{source_adapter}:{source_tool}'`` with defensive fallbacks.

    Defensive defaults guard against malformed AdapterResult construction
    (empty ``source_adapter`` / ``source_tool``) so the ledger row at least
    identifies the row as adapter-origin (``adapter:unknown``) rather than
    crashing or rendering an empty colon-prefixed string.
    """
    adapter = ar.source_adapter or "adapter"
    tool = ar.source_tool or "unknown"
    return f"{adapter}:{tool}"


def build_scope_ledger(
    walker_result: WalkerResult,
    collector_results: list[CollectorResult],
    *,
    repo_path: Path,
    adapter_results: list[AdapterResult] | None = None,
) -> ScopeLedger:
    """Assemble the ScopeLedger from walker + collectors + adapters.

    Args:
        walker_result: output of ``build_repo_index(repo_path)``.
        collector_results: list of ``CollectorResult`` from ``run_collectors()``.
        repo_path: target repo root (used for relative-path conversion).
        adapter_results: Phase 3+ list of ``AdapterResult`` from
            ``run_adapters()``. ``None`` defaults to ``[]`` for Phase 2
            backward compatibility.

    Returns:
        ``ScopeLedger`` with scanned/skipped/unavailable + notes populated.
    """
    repo_path = Path(repo_path).resolve()
    adapter_results = adapter_results or []

    # Scanned: one entry per top-level walked dir.
    # collectors = sorted union of {collector source names} ∪ {adapter labels}.
    collector_names = {
        r.source_collector for r in collector_results if r.source_collector
    }
    adapter_names = {_adapter_label(ar) for ar in adapter_results}
    all_names = sorted(collector_names | adapter_names)

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
            collectors=all_names,
        ))

    # Skipped: one entry per walker_result.skipped_dirs.
    skipped: list[SkippedEntry] = []
    for d, reason in walker_result.skipped_dirs:
        try:
            rel = str(d.relative_to(repo_path))
        except ValueError:
            rel = str(d)
        skipped.append(SkippedEntry(dir=rel, reason=reason))

    # Unavailable: one entry per non-ok CollectorResult + one per non-ok
    # AdapterResult.
    unavailable: list[UnavailableEntry] = []
    for r in collector_results:
        if r.status != "ok":
            unavailable.append(UnavailableEntry(
                dimension=r.dimension or "unknown",
                collector=r.source_collector or "unknown",
                reason=r.notes or r.status,
            ))
    for ar in adapter_results:
        if ar.status != "ok":
            unavailable.append(UnavailableEntry(
                dimension=ar.dimension or "unknown",
                collector=_adapter_label(ar),
                reason=ar.notes or ar.status,
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
