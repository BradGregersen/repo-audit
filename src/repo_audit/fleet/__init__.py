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

from repo_audit.fleet.aggregate import (
    aggregate,
    build_repo_row,
    make_failed_row,
)
from repo_audit.fleet.discovery import DiscoveryResult, discover_repos

__all__ = [
    "DiscoveryResult",
    "aggregate",
    "build_repo_row",
    "discover_repos",
    "make_failed_row",
]
