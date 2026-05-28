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


def run_collectors(repo_path: Path, repo_index: dict) -> list[CollectorResult]:
    """D-24 sequential; D-25 never raises across boundary.

    Per-collector timing is captured via time.perf_counter; the resulting
    duration_ms field surfaces in the ScopeLedger's Unavailable subsection
    when a collector hits the soft 60s budget (Phase 2 default).
    """
    results: list[CollectorResult] = []
    for fn in _REGISTRY:
        t0 = time.perf_counter()
        try:
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
