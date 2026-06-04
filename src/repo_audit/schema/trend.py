"""Trend-delta contracts (TREND-01/02/03).

These models carry the pure-Python-computed deltas between a prior and current
``ScanReport`` plus the three-way finding classification. The agent never
computes or invents any of these numbers (TREND-02 / D-05-07) — they are
produced deterministically by ``trend.delta.compute_trend``.

SAFE-04/08 honesty contract: a delta of ``None`` means "metric unavailable on
at least one side" (n/a) — NEVER a fabricated ``0``. A real ``0`` (e.g. zero
lint errors on both scans) is a genuine measured value.
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# The three-way classification (RESEARCH Pitfall 2 — the SC-2 contract).
FindingChangeStatus = Literal[
    "resolved",  # prior-ref gone from current AND file still present (a genuine fix)
    "vanished_with_file",  # prior-ref gone AND file deleted (NOT a fix — anti-cheating)
    "still_present",  # prior-ref present in current
]


class FindingChange(BaseModel):
    """One prior finding's fate in the current scan.

    The ``finding_ref`` is the shared composite key
    ``{source_tool}::{rule_id}::{file}:{line}`` (see
    ``trend.delta.composite_finding_ref``). ``status`` is the Pitfall-2
    classification.
    """

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    dimension: str
    severity: str
    status: FindingChangeStatus
    file: str | None = None


class TrendDelta(BaseModel):
    """All deltas the trend section of the report needs.

    Every ``*_delta`` is ``int | float | None``: ``None`` when the underlying
    metric is unavailable on either side (SAFE-04/08), never a fabricated 0.
    ``finding_count_delta_by_dimension`` always covers the full 7-dimension
    taxonomy (exhaustive).
    """

    model_config = ConfigDict(extra="forbid")

    prior_baseline_date: date
    commits_delta: int | None = None
    loc_delta: int | None = None
    lint_error_delta: int | None = None
    coverage_delta: float | None = None
    web_transfer_size_delta: int | None = None
    """current − prior web transfer bytes; ``None`` (n/a) when either side is
    absent / unavailable (SAFE-04/08) — NEVER a fabricated ``0``. A distinct
    per-surface field (web transfer vs RN bundle are different units), never
    derived from ``loc_delta`` (SC3 separability)."""
    rn_bundle_size_delta: int | None = None
    """current − prior RN bundle bytes; ``None`` (n/a) when either side is
    absent / unavailable (SAFE-04/08) — NEVER a fabricated ``0``. Separate from
    ``web_transfer_size_delta`` (different units) and from ``loc_delta`` (SC3)."""
    finding_count_delta_by_dimension: dict[str, int] = Field(default_factory=dict)
    changes: list[FindingChange] = Field(default_factory=list)
    prior_totals: dict[str, float | int] = Field(default_factory=dict)
    """Prior-scan absolute metric totals (commits/loc/lint/coverage).

    Plan 05-03 faithfulness fold (RESEARCH Pitfall 1): the agent's trend
    narrative phrases movement as "rose from {prior} to {current} (+{delta})".
    The delta and current values trace to the Finding store + delta magnitudes,
    but the PRIOR absolute total does not — it lives only on the prior sidecar.
    Exposing it here lets ``build_allowed_numbers`` admit the prior totals so
    the full "from X to Y (+D)" sentence survives the gate. Keyed by metric
    family ("commits"/"loc"/"lint"/"coverage"); a key is omitted when that
    metric was unavailable on the prior side (SAFE-04/08 — never a fake 0)."""


__all__ = [
    "FindingChangeStatus",
    "FindingChange",
    "TrendDelta",
]
