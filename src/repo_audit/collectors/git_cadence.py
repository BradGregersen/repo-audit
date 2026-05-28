"""COLL-01: git cadence collector (commits/windows/contributors via pygit2).

Stub until Plan 02-02 lands the implementation. Status reports
'unavailable' so the orchestrator + ledger wiring (Plan 02-06) can be
end-to-end tested without git_cadence being functional.
"""
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    return CollectorResult(
        status="unavailable",
        notes="not implemented yet (Plan 02-02)",
        source_collector="git_cadence",
        dimension="process",
    )
