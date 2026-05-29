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
from typing import TYPE_CHECKING

from repo_audit.adapters.base import AdapterResult
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.scope_ledger import (
    ScannedEntry,
    ScopeLedger,
    SkippedEntry,
    UnavailableEntry,
)
from repo_audit.walker.repo_index import WalkerResult

if TYPE_CHECKING:
    from repo_audit.schema.detection import DetectionResult


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


# ============================================================
# Plan 04-09 — D-60 post-flight ledger-gap auto-fill (AGENT-07)
# ============================================================
# UNIVERSAL_REQUIRED_COLLECTORS: the 6 Phase 2 collectors that MUST always
# have at least one ledger row — a Finding sourced from them OR a
# scope_ledger.unavailable entry naming them. Derived from
# collectors/__init__.py's registry order.
UNIVERSAL_REQUIRED_COLLECTORS: tuple[str, ...] = (
    "git_cadence",
    "loc_inventory",
    "secret_detection",
    "doc_presence",
    "todo_markers",
    "file_size_cap",
)


def _has_ledger_row(
    collector_name: str,
    findings: list,
    scope_ledger: ScopeLedger,
) -> bool:
    """True iff findings or scope_ledger.unavailable references collector_name.

    Adapter rows live under the ``"{adapter}:{tool}"`` shape (Phase 3 D-30),
    so an adapter tool ``tsc`` matches either the bare ``tsc`` row OR a
    ``typescript-node:tsc`` row.
    """
    if any(getattr(f, "source_collector", "") == collector_name for f in findings):
        return True
    if any(getattr(f, "source_tool", "") == collector_name for f in findings):
        return True
    for u in scope_ledger.unavailable:
        coll = getattr(u, "collector", "")
        if coll == collector_name or coll.endswith(f":{collector_name}"):
            return True
    return False


def _invoke_collector_by_name(
    name: str,
    repo_path: "Path",
    walker_index: dict,
) -> CollectorResult | None:
    """Locate a collector by its module name in the registry; invoke + return.

    The collector registry stores each module's ``run`` callable. Universal
    collector modules are named after the collector (``...collectors.git_cadence``),
    so we match the registered callable's ``__module__`` against the target
    name. Returns ``None`` if the collector cannot be located (registry bug).
    NEVER raises — a buggy collector degrades to an ``unavailable``-shape
    result so the ledger row still gets populated (D-67 honesty contract).
    """
    from repo_audit.collectors import get_registry

    for fn in get_registry():
        mod = getattr(fn, "__module__", "")
        if mod.endswith(f".{name}") or mod.endswith(f".collectors.{name}"):
            try:
                return fn(repo_path, walker_index)
            except Exception as exc:  # noqa: BLE001 — defense in depth (D-67)
                return CollectorResult(
                    status="unavailable",
                    notes=f"auto-fill invocation failed: {type(exc).__name__}: {exc}",
                    source_collector=name,
                )
    return None


def _adapter_required_collectors(detection: "DetectionResult") -> list[str]:
    """Walk ``adapter.yaml.required_collectors`` for every detected stack.

    The adapter registry maps a stack name to its ``run`` callable (not the
    module), so the adapter's ``ADAPTER_CONFIG`` is resolved via
    ``sys.modules[run_fn.__module__]`` — the same indirection Plan 04-04's
    ``adapter_tool_names`` uses. Stacks with no registered adapter are
    silently skipped (D-40 graceful degradation).
    """
    import sys

    from repo_audit.adapters import get_adapter_registry

    out: list[str] = []
    registry = get_adapter_registry()
    for profile in detection.stacks:
        run_fn = registry.get(profile.stack)
        if run_fn is None:
            continue
        module = sys.modules.get(getattr(run_fn, "__module__", ""))
        if module is None:
            continue
        config = getattr(module, "ADAPTER_CONFIG", None) or getattr(
            module, "CONFIG", None
        )
        if not config:
            continue
        required = config.get("required_collectors", []) or []
        out.extend(required)
    return out


def auto_fill_ledger_gaps(
    findings: list,
    scope_ledger: ScopeLedger,
    detection: "DetectionResult",
    *,
    repo_path: "Path",
    walker_index: dict,
) -> tuple[list, ScopeLedger]:
    """D-60 post-flight ledger-completeness check (AGENT-07).

    Iterate ``UNIVERSAL_REQUIRED_COLLECTORS`` + every detected adapter's
    ``adapter.yaml.required_collectors``; for each name without a ledger row
    (in ``findings`` OR ``scope_ledger.unavailable``), re-invoke the collector
    deterministically and append the resulting findings (or an unavailable
    row when the collector cannot be located / returned non-ok). Always log
    auto-fill events to ``scope_ledger.notes`` per D-60.

    Under D-57 read-only tools this code path is essentially unreachable for
    happy-path scans (collectors ran before the agent booted; the agent
    cannot skip them). The mechanism stays as defense in depth for:
      - Phase 6+ action-tool semantics
      - a collector exception swallowed at execute time
      - a bug in the collector registry shape

    ALWAYS returns ``(findings, scope_ledger)``. NEVER raises (D-67 exit-0).
    """
    required_names = list(UNIVERSAL_REQUIRED_COLLECTORS) + _adapter_required_collectors(
        detection
    )
    new_findings = list(findings)
    gap_notes: list[str] = []
    seen: set[str] = set()
    for name in required_names:
        if name in seen:
            continue
        seen.add(name)
        if _has_ledger_row(name, new_findings, scope_ledger):
            continue
        gap_notes.append(
            f"gap auto-filled: {name} had no row at post-flight check"
        )
        result = _invoke_collector_by_name(name, repo_path, walker_index)
        if result is None:
            scope_ledger.unavailable.append(
                UnavailableEntry(
                    dimension="unknown",
                    collector=name,
                    reason="auto-fill could not locate collector in registry",
                )
            )
        elif result.status != "ok":
            scope_ledger.unavailable.append(
                UnavailableEntry(
                    dimension=result.dimension or "unknown",
                    collector=result.source_collector or name,
                    reason=result.notes or result.status,
                )
            )
        else:
            new_findings.extend(result.findings)

    if gap_notes:
        note_text = "; ".join(gap_notes)
        if scope_ledger.notes:
            scope_ledger.notes = scope_ledger.notes + "; " + note_text
        else:
            scope_ledger.notes = note_text

    return new_findings, scope_ledger
