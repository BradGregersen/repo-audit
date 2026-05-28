"""COLL-02: LOC + file inventory via vendored scc binary.

Stub until Plan 02-03 lands the implementation + vendored binaries.
"""
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    return CollectorResult(
        status="unavailable",
        notes="not implemented yet (Plan 02-03)",
        source_collector="loc_inventory",
        dimension="quality",
    )
