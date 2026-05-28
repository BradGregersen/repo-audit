"""COLL-03: gitleaks-or-backstop secret detection per D-35.

Stub until Plan 02-04 lands the implementation.
"""
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    return CollectorResult(
        status="unavailable",
        notes="not implemented yet (Plan 02-04)",
        source_collector="secret_detection",
        dimension="security",
    )
