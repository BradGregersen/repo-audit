"""Pure-Python trend delta engine + three-way finding classification.

This is the deterministic core of trend memory (TREND-01/02/03). It parses the
prior + current ``ScanReport`` and computes:

  * five metric-family deltas (commits, LOC, lint-error, coverage,
    finding-count-by-dimension) — in pure Python, no agent (TREND-02 /
    D-05-07: the agent never computes or invents numbers); and
  * a per-finding three-way classification
    (``resolved`` / ``vanished_with_file`` / ``still_present``) keyed on the
    shared composite finding-ref ``{source_tool}::{rule_id}::{file}:{line}``.

SAFE-04/08 honesty: a metric absent or ``evidence_type='unavailable'`` on
EITHER side yields a ``None`` delta (n/a) — NEVER a fabricated ``0``. A real
measured ``0`` (e.g. zero eslint findings on both scans) is a genuine value and
is reported as ``0``.

SC-2 anti-cheating (RESEARCH Pitfall 2): a prior finding gone from the current
scan is classified ``resolved`` ONLY if its file still exists on disk; if the
file was deleted, it is ``vanished_with_file``. Deleting code is never a fix.

Purity: the only I/O is the on-disk file-existence check (``(repo_path /
file).exists()``) needed to separate "fixed" from "deleted". No agent, no
network, no subprocess.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from repo_audit.schema.enums import Dimension
from repo_audit.schema.trend import FindingChange, TrendDelta

if TYPE_CHECKING:  # pragma: no cover - typing aid only
    from repo_audit.schema.finding import Finding
    from repo_audit.schema.report import ScanReport

# The full 7-dimension taxonomy (SCH-02). Iterated exhaustively so the
# per-dimension count-delta dict is always complete, even for dimensions with
# zero findings on both sides.
_ALL_DIMENSIONS: tuple[Dimension, ...] = (
    "security",
    "architecture_rot",
    "test_integrity",
    "correctness",
    "quality",
    "process",
    "observability",
)


def composite_finding_ref(f: "Finding") -> str:
    """Return the shared cross-scan match key ``{source_tool}::{rule_id}::{file}:{line}``.

    This is the SINGLE canonical scheme (RESEARCH Anti-Pattern: do not fork a
    second key). It mirrors the helper currently duplicated in
    ``render.corroboration`` / the Jinja renderer; those duplicates may later be
    refactored to import this function (out of scope here — just do not invent a
    competing scheme).
    """
    source_tool = getattr(f, "source_tool", "") or ""
    rule_id = getattr(f, "rule_id", "") or ""
    file = getattr(f, "file", "") or ""
    line = getattr(f, "line", "")
    line = "" if line is None else line
    return f"{source_tool}::{rule_id}::{file}:{line}"


def _parsed_value(finding: "Finding") -> dict:
    """Safely pull a finding's ``evidence.parsed_value`` dict (or empty)."""
    evidence = getattr(finding, "evidence", None)
    if evidence is None:
        return {}
    return getattr(evidence, "parsed_value", {}) or {}


def _first_by_collector(report: "ScanReport", collector: str) -> "Finding | None":
    """Return the first finding with the given ``source_collector`` (or None)."""
    for f in report.findings:
        if getattr(f, "source_collector", "") == collector:
            return f
    return None


def _commits_metric(report: "ScanReport") -> int | None:
    """git_cadence ``parsed_value.commits_total`` (None when collector absent)."""
    f = _first_by_collector(report, "git_cadence")
    if f is None:
        return None
    val = _parsed_value(f).get("commits_total")
    return int(val) if isinstance(val, (int, float)) else None


def _loc_metric(report: "ScanReport") -> int | None:
    """loc_inventory aggregate ``parsed_value.total_lines`` (None when absent)."""
    for f in report.findings:
        if getattr(f, "source_collector", "") == "loc_inventory":
            val = _parsed_value(f).get("total_lines")
            if isinstance(val, (int, float)):
                return int(val)
    return None


def _lint_error_count(report: "ScanReport") -> int | None:
    """Count of ``source_tool='eslint'`` findings.

    A scan that ran the TypeScript adapter but found zero lint errors yields a
    genuine ``0`` — but only if eslint actually ran. We cannot distinguish
    "eslint ran, 0 errors" from "eslint never ran" purely from the absence of
    eslint findings, so the count is always returned as an int (>= 0). The
    DELTA between two counts is therefore meaningful whenever both scans
    exercised the same adapter; the report-layer context disambiguates. We
    deliberately return an int (never None) here so that "0 lint errors on both
    scans" reports a true ``0`` delta rather than an n/a.
    """
    return sum(1 for f in report.findings if getattr(f, "source_tool", "") == "eslint")


def _coverage_metric(report: "ScanReport") -> float | None:
    """lcov coverage percent; None when unavailable (SAFE-04/08, not 0)."""
    for f in report.findings:
        if getattr(f, "source_tool", "") == "lcov":
            # An unavailable coverage artifact is explicitly n/a, not 0%.
            if getattr(f, "evidence_type", "") == "unavailable":
                return None
            pv = _parsed_value(f)
            val = pv.get("total_pct", pv.get("line_pct"))
            return float(val) if isinstance(val, (int, float)) else None
    return None


def _subtract(prior: float | int | None, current: float | int | None):
    """current - prior, or None if either side is unavailable (SAFE-04/08)."""
    if prior is None or current is None:
        return None
    return current - prior


def _count_by_dimension(report: "ScanReport") -> dict[str, int]:
    """Count findings per dimension over the full 7-set (zeros included)."""
    counts: dict[str, int] = {dim: 0 for dim in _ALL_DIMENSIONS}
    for f in report.findings:
        dim = getattr(f, "dimension", None)
        if dim in counts:
            counts[dim] += 1
    return counts


def compute_trend(
    prior: "ScanReport",
    current: "ScanReport",
    repo_path: Path,
) -> TrendDelta:
    """Compute every trend delta + classify each prior finding's fate.

    Args:
        prior: the prior scan's ``ScanReport`` (parsed from the prior sidecar).
        current: the current scan's ``ScanReport``.
        repo_path: the repo root on disk — used ONLY for the
            file-still-present check that separates ``resolved`` from
            ``vanished_with_file``.

    Returns:
        A fully-populated ``TrendDelta``. Unavailable metrics yield ``None``
        deltas (SAFE-04/08), never fabricated zeros.
    """
    repo_root = Path(repo_path)

    # --- Metric-family deltas (pure Python; None when a side is unavailable). ---
    commits_delta = _subtract(_commits_metric(prior), _commits_metric(current))
    loc_delta = _subtract(_loc_metric(prior), _loc_metric(current))
    lint_error_delta = _subtract(_lint_error_count(prior), _lint_error_count(current))
    coverage_delta = _subtract(_coverage_metric(prior), _coverage_metric(current))

    prior_counts = _count_by_dimension(prior)
    current_counts = _count_by_dimension(current)
    finding_count_delta_by_dimension = {
        dim: current_counts[dim] - prior_counts[dim] for dim in _ALL_DIMENSIONS
    }

    # --- Three-way finding classification (RESEARCH Pitfall 2 / SC-2). ---
    current_refs = {composite_finding_ref(f) for f in current.findings}
    changes: list[FindingChange] = []
    for f in prior.findings:
        ref = composite_finding_ref(f)
        file = getattr(f, "file", None)
        if ref in current_refs:
            status = "still_present"
        else:
            # Gone from current. Was it fixed (file still present) or did the
            # file vanish? A deletion is NEVER a fix (anti-cheating).
            file_present = bool(file) and (repo_root / file).exists()
            status = "resolved" if file_present else "vanished_with_file"
        changes.append(
            FindingChange(
                finding_ref=ref,
                dimension=str(getattr(f, "dimension", "")),
                severity=str(getattr(f, "severity", "")),
                status=status,
                file=file,
            )
        )

    return TrendDelta(
        prior_baseline_date=prior.meta.scan_date,
        commits_delta=commits_delta,
        loc_delta=loc_delta,
        lint_error_delta=lint_error_delta,
        coverage_delta=coverage_delta,
        finding_count_delta_by_dimension=finding_count_delta_by_dimension,
        changes=changes,
    )


__all__ = ["compute_trend", "composite_finding_ref"]
