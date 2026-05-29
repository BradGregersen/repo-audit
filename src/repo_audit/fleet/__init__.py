"""Fleet roll-up package: discovery + JSON-sidecar aggregation (Phase 5, Wave 2).

Public surface:
- ``discover_repos(root)`` — immediate ``.git`` children under a sweep root
  (FLEET-01). See ``fleet.discovery``.
- ``aggregate(rows, ...)`` / ``build_repo_row(...)`` / ``make_failed_row(...)``
  — build a ``FleetSnapshot`` from per-repo JSON sidecars ONLY, never the
  markdown (FLEET-02 / SC-6). See ``fleet.aggregate``.

The CLI sweep loop, dashboard rendering, and any Command Center wiring are NOT
here — they land in Plan 05-05 (and beyond).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "DiscoveryResult",
    "aggregate",
    "build_repo_row",
    "discover_repos",
    "make_failed_row",
]

if TYPE_CHECKING:  # pragma: no cover - typing aid only
    from repo_audit.fleet.aggregate import (
        aggregate,
        build_repo_row,
        make_failed_row,
    )
    from repo_audit.fleet.discovery import DiscoveryResult, discover_repos


# PEP 562 lazy re-export: importing one submodule (e.g. fleet.discovery) must
# not force-import its sibling (fleet.aggregate). Keeps the modules
# independently importable and avoids a hard import cycle through the package
# init when only one half of the surface is needed.
_LAZY = {
    "DiscoveryResult": "repo_audit.fleet.discovery",
    "discover_repos": "repo_audit.fleet.discovery",
    "aggregate": "repo_audit.fleet.aggregate",
    "build_repo_row": "repo_audit.fleet.aggregate",
    "make_failed_row": "repo_audit.fleet.aggregate",
}


def __getattr__(name: str) -> Any:
    module_path = _LAZY.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, name)
