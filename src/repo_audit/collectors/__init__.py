"""Phase 2 collector registry (D-23..D-25).

Each collector module imports `register_collector` from here and applies
it as a decorator to its `run(repo_path, repo_index)` function. Importing
each collector module at the bottom of this file fires the decorator at
package import time, populating the registry in stable order
(Claude's-Discretion line in 02-CONTEXT.md).

The orchestrator `run_collectors(repo_path, repo_index)` executes the
registry SEQUENTIALLY (D-24). It is the last line of defense against an
unhandled exception escaping a collector (D-25); collectors should also
wrap their own bodies in try/except and return CollectorResult(status=
'unavailable', notes=<reason>) — the orchestrator's wrapper is a backstop.
"""
from __future__ import annotations

import inspect
import time
from pathlib import Path
from typing import Callable

from repo_audit.collectors.base import CollectorResult

CollectorFn = Callable[[Path, dict], CollectorResult]

_REGISTRY: list[CollectorFn] = []


def register_collector(fn: CollectorFn) -> CollectorFn:
    """Decorator: append fn to the module-level registry tuple (D-23)."""
    _REGISTRY.append(fn)
    return fn


def get_registry() -> tuple[CollectorFn, ...]:
    return tuple(_REGISTRY)


def _accepts_deadline(fn: CollectorFn) -> bool:
    """True when ``fn`` declares a ``deadline`` parameter.

    Used so ``run_collectors`` only threads the shared scan deadline into
    collectors that opt in (the read-heavy / subprocess ones). Collectors and
    test doubles with the plain ``(repo_path, repo_index)`` signature are called
    unchanged. Inspection failures degrade to "does not accept" (safe default).
    """
    try:
        return "deadline" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def run_collectors(
    repo_path: Path,
    repo_index: dict,
    *,
    deadline: float | None = None,
) -> list[CollectorResult]:
    """D-24 sequential; D-25 never raises across boundary.

    Per-collector timing is captured via time.perf_counter; the resulting
    duration_ms field surfaces in the ScopeLedger's Unavailable subsection
    when a collector hits the soft 60s budget (Phase 2 default).

    SCAN-BOUND-01 (D-051-06): ``deadline`` is an optional ``time.perf_counter``
    value. BEFORE invoking each collector, if the deadline has passed, the
    collector (and every remaining one) is marked ``status='timeout'`` with a
    notes string INSTEAD of being run — a deterministic between-collector
    check, never a mid-flight kill (no partial-read corruption). A
    ``status != 'ok'`` result already flows to the ledger's unavailable
    section and flips the scan to partial. ``deadline=None`` (the default)
    preserves the exact prior behaviour for every existing caller/test.

    Per-collector self-bounding: the between-collector check above cannot
    interrupt a single collector once it is running. On a very large monorepo the
    content-read / subprocess collectors (todo_markers, secret_detection,
    loc_inventory) each ran 110-145 s unbounded. So ``deadline`` is now ALSO
    threaded INTO each collector that declares a ``deadline`` keyword parameter;
    those collectors poll it from inside their own loops / cap their subprocess
    timeouts at the remaining budget and self-report ``status != 'ok'`` when a
    bound trips. Collectors without the parameter (and the monkeypatched test
    doubles) are called exactly as before — the keyword is passed conditionally
    via signature inspection so no collector contract is forced to change.
    """
    results: list[CollectorResult] = []
    budget_exceeded = False
    for fn in _REGISTRY:
        name = getattr(fn, "__module__", getattr(fn, "__name__", "<unknown>"))
        name = name.rsplit(".", 1)[-1]
        # SCAN-BOUND-01: deterministic between-collector deadline check.
        if budget_exceeded or (
            deadline is not None and time.perf_counter() > deadline
        ):
            budget_exceeded = True
            results.append(CollectorResult(
                status="timeout",
                notes=f"per-scan time budget exceeded; {name} skipped",
                source_collector=name,
            ))
            continue
        t0 = time.perf_counter()
        try:
            if _accepts_deadline(fn):
                r = fn(repo_path, repo_index, deadline=deadline)
            else:
                r = fn(repo_path, repo_index)
        except Exception as exc:
            r = CollectorResult(
                status="unavailable",
                notes=f"{type(exc).__name__}: {exc}",
                source_collector=getattr(fn, "__name__", "<unknown>"),
            )
        r.duration_ms = (time.perf_counter() - t0) * 1000.0
        results.append(r)
    return results


# Stable registry order (Claude's Discretion in 02-CONTEXT.md):
# git_cadence -> loc_inventory -> doc_presence -> todo_markers ->
# file_size_cap -> secret_detection (secrets last so the ledger reads
# dimension-by-dimension naturally).
from repo_audit.collectors import git_cadence       # noqa: F401,E402
from repo_audit.collectors import loc_inventory     # noqa: F401,E402
from repo_audit.collectors import doc_presence      # noqa: F401,E402
from repo_audit.collectors import todo_markers      # noqa: F401,E402
from repo_audit.collectors import file_size_cap     # noqa: F401,E402
from repo_audit.collectors import secret_detection  # noqa: F401,E402

__all__ = [
    "CollectorResult",
    "register_collector",
    "get_registry",
    "run_collectors",
]
