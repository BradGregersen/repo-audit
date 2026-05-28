"""COLL-06: per-ext line-count cap (DEFAULT_SIZE_CAPS, get_threshold).

Stub until Plan 02-05 lands the implementation.
"""
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    return CollectorResult(
        status="unavailable",
        notes="not implemented yet (Plan 02-05)",
        source_collector="file_size_cap",
        dimension="quality",
    )
