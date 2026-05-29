"""Fleet aggregator: per-repo JSON sidecars -> FleetSnapshot (FLEET-02 / SC-6).

This module is the deterministic roll-up core. It reads ONLY the per-repo JSON
sidecars (``*.json`` ScanReport serializations) — NEVER the markdown reports.
Editing a report's ``.md`` has zero effect on the aggregated ``FleetSnapshot``
(SC-6, proven by ``tests/test_fleet_aggregate.py::test_reads_json_not_md``).

All numbers are computed here in Python (CLAUDE.md reproducibility constraint —
the agent never invents fleet figures). Hostile/corrupt sidecars are tolerated:
a parse failure yields a ``status='failed'`` row, never a crash (T-05-05).

Last-commit recency is derived HERE via pygit2 on ``repo_path`` (open-question
Q1 lock: keeps Phase 5 to zero collector changes), not by a collector leaf.

Severity counting: ``severity_by_dimension[dimension][severity]`` over the
7-dimension taxonomy, counting only the actionable rungs
``blocker``/``critical``/``major`` (``COUNTED_SEVERITIES``). Minor/info are the
long tail and are intentionally excluded from the fleet view.

Coverage: read from the lcov coverage finding's
``parsed_value['total_pct']`` when present; ``None`` otherwise (NEVER coerced
to ``0.0`` — SAFE-04: a real 0% must not be indistinguishable from "no data").
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from pydantic import ValidationError

from repo_audit.schema.fleet import (
    COUNTED_SEVERITIES,
    FleetRepoRow,
    FleetSnapshot,
)
from repo_audit.schema.report import ScanReport

# The lcov coverage finding contract (adapters/typescript/parsers/lcov.py):
# source_tool='lcov', rule_id='coverage_summary', parsed_value['total_pct'].
_COVERAGE_SOURCE_TOOL = "lcov"
_COVERAGE_RULE_ID = "coverage_summary"
_COVERAGE_PCT_KEY = "total_pct"


def _last_commit_iso(repo_path: Path) -> str | None:
    """Return the ISO-8601 timestamp of HEAD's commit, or None on any failure.

    Open-question Q1 decision: recency is computed in the aggregator via
    pygit2 (the aggregator already holds ``repo_path``), NOT by adding a git
    collector. Returns ``None`` for an UNCOMMITTED repo, a non-repo path, or
    any pygit2 read error — render as ``n/a`` downstream.
    """
    try:
        import pygit2
    except Exception:  # pragma: no cover — pygit2 is a hard dep, defensive only
        return None
    try:
        repo = pygit2.Repository(str(repo_path))
        commit = repo[repo.head.target]
        tz = _dt.timezone(_dt.timedelta(minutes=commit.commit_time_offset))
        dt = _dt.datetime.fromtimestamp(commit.commit_time, tz=tz)
        return dt.isoformat()
    except Exception:
        # No commits (fresh init), not a repo, detached/empty HEAD, or any
        # libgit2 error → no recency signal. Never crash the roll-up.
        return None


def _coverage_pct(report: ScanReport) -> float | None:
    """Extract repo-level line coverage from the lcov finding, or None.

    Reads ``parsed_value['total_pct']`` from the static coverage finding. An
    ``unavailable`` coverage finding has no ``total_pct`` → None (NOT 0.0).
    """
    for finding in report.findings:
        if (
            finding.source_tool == _COVERAGE_SOURCE_TOOL
            and finding.rule_id == _COVERAGE_RULE_ID
        ):
            value = finding.evidence.parsed_value.get(_COVERAGE_PCT_KEY)
            if isinstance(value, (int, float)):
                return float(value)
            return None
    return None


def _severity_by_dimension(report: ScanReport) -> dict[str, dict[str, int]]:
    """Count blocker/critical/major findings per dimension.

    Returns ``{dimension: {severity: count}}`` containing only dimensions that
    have at least one counted finding, and within each, only the counted
    severities that occurred (no zero-filled noise).
    """
    counts: dict[str, dict[str, int]] = {}
    for finding in report.findings:
        if finding.severity not in COUNTED_SEVERITIES:
            continue
        dim_bucket = counts.setdefault(finding.dimension, {})
        dim_bucket[finding.severity] = dim_bucket.get(finding.severity, 0) + 1
    return counts


def build_repo_row(repo_path: Path, sidecar_json_path: Path) -> FleetRepoRow:
    """Build a FleetRepoRow from a per-repo JSON sidecar (JSON ONLY — SC-6).

    Parses ``sidecar_json_path`` via ``ScanReport.model_validate_json`` (the
    markdown sibling is never read). On any parse/read failure returns a
    ``status='failed'`` row with ``error_reason`` (T-05-05) — never raises.

    The slug falls back to the repo dir name when a failed parse leaves no
    authoritative ``meta.repo_slug`` to read.
    """
    repo_path = Path(repo_path)
    sidecar_json_path = Path(sidecar_json_path)
    try:
        text = sidecar_json_path.read_text(encoding="utf-8")
        report = ScanReport.model_validate_json(text)
    except (ValidationError, json.JSONDecodeError, OSError, ValueError) as e:
        return make_failed_row(
            repo_path,
            error_reason=f"sidecar parse failed: {type(e).__name__}: {e}",
        )

    meta = report.meta
    return FleetRepoRow(
        repo_slug=meta.repo_slug,
        repo_path=str(repo_path),
        status="ok",
        error_reason=None,
        commit_sha=meta.commit_sha,
        last_commit_iso=_last_commit_iso(repo_path),
        scan_date=meta.scan_date,
        severity_by_dimension=_severity_by_dimension(report),
        coverage_pct=_coverage_pct(report),
        scan_cost_usd=meta.total_cost_usd,
        scan_seconds=meta.wall_clock_seconds,
    )


def make_failed_row(repo_path: Path, error_reason: str) -> FleetRepoRow:
    """Build a ``status='failed'`` row for a repo whose scan never produced a
    usable sidecar (the sweep loop in Plan 05-05 catches the scan exception and
    calls this, or ``build_repo_row`` calls it on a corrupt sidecar).

    The slug is the repo directory name (no sidecar to read an authoritative
    one from). All metric fields stay ``None``/empty.
    """
    repo_path = Path(repo_path)
    return FleetRepoRow(
        repo_slug=repo_path.name,
        repo_path=str(repo_path),
        status="failed",
        error_reason=error_reason,
        last_commit_iso=_last_commit_iso(repo_path),
    )


def aggregate(
    rows: list[FleetRepoRow],
    *,
    sweep_root: Path | str,
    generated_date: _dt.date,
    total_cost_usd: float | None = None,
    sweep_seconds: float | None = None,
) -> FleetSnapshot:
    """Assemble a FleetSnapshot from per-repo rows.

    Fleet-wide ``total_blockers``/``total_critical`` sum the per-dimension
    counts across ``'ok'`` rows only (failed rows have no usable counts).
    ``failed_count`` counts ``'failed'`` rows. ``total_cost_usd`` and
    ``sweep_seconds`` are passed through from the caller (the sweep loop owns
    the wall-clock + cost tally); ``None`` is preserved, never coerced to 0.
    """
    total_blockers = 0
    total_critical = 0
    failed_count = 0
    for row in rows:
        if row.status == "failed":
            failed_count += 1
            continue
        for dim_bucket in row.severity_by_dimension.values():
            total_blockers += dim_bucket.get("blocker", 0)
            total_critical += dim_bucket.get("critical", 0)

    return FleetSnapshot(
        generated_date=generated_date,
        sweep_root=str(sweep_root),
        total_repos=len(rows),
        total_blockers=total_blockers,
        total_critical=total_critical,
        failed_count=failed_count,
        total_cost_usd=total_cost_usd,
        sweep_seconds=sweep_seconds,
        repos=list(rows),
    )
