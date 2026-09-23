"""Fleet roll-up contract — the documented, versioned consumer artifact (D-05-02).

This module defines the JSON shape written to
``repo-audit/reports/fleet-{YYYY-MM-DD}.json`` by ``repo-audit fleet`` (Plan
05-05). Unlike the per-repo ``ScanReport`` sidecar (which is an internal
serialization of one scan), ``FleetSnapshot`` is a **deliberately-designed,
independently-versioned public contract**: a future dashboard consumer is
intended to read it as a drop-in reader.
For that reason every field is documented here, the model is
``extra='forbid'`` (a reader can rely on the exact key set), and the snapshot
carries its OWN ``schema_version`` that is independent of ``ScanReport``'s — a
bump to the per-repo sidecar schema does not implicitly bump this contract, and
vice versa.

The aggregator (``fleet/aggregate.py``) builds these models from the per-repo
JSON sidecars ONLY (never the markdown — SC-6 / FLEET-02). Numbers are computed
in Python by the aggregator; the agent never invents them (CLAUDE.md
reproducibility constraint).

----------------------------------------------------------------------------
FleetRepoRow — one row per repo discovered under the sweep root.
----------------------------------------------------------------------------

repo_slug
    The per-repo slug (``meta.repo_slug`` from the sidecar). Stable identifier
    a consumer can use as a primary key for a fleet table row.

repo_path
    Absolute path to the repo on the sweep host. Provenance / drill-down link.

status
    ``'ok'`` when a sidecar was found and parsed into a ScanReport;
    ``'failed'`` when the scan crashed before writing a sidecar OR the sidecar
    was corrupt / unparseable. A consumer renders failed rows distinctly and
    must NOT assume the metric fields are populated.

error_reason
    Human-readable reason a row is ``'failed'`` (exception type + message, or
    a parse-failure note). ``None`` on ``'ok'`` rows.

commit_sha
    ``meta.commit_sha`` from the sidecar. May be the literal ``'UNCOMMITTED'``
    for a repo with no commits, or ``None`` on a failed row. Display verbatim;
    do NOT coerce ``'UNCOMMITTED'`` to empty.

last_commit_iso
    ISO-8601 timestamp of the repo's HEAD commit, computed by the AGGREGATOR
    via pygit2 on ``repo_path`` (open-question Q1 lock: recency is derived in
    the roll-up, NOT by a collector — keeps Phase 5 to zero collector changes).
    ``None`` when the repo has no commits, is not a git repo, or the read
    failed. Render as ``n/a`` downstream.

scan_date
    ``meta.scan_date`` from the sidecar (the date the scan ran). ``None`` on a
    failed row.

severity_by_dimension
    ``{dimension: {severity: count}}`` over the 7-dimension taxonomy, counting
    only the actionable rungs ``blocker``/``critical``/``major`` per dimension.
    Empty dict on a failed row. A consumer sums or pivots this for a heatmap.

coverage_pct
    Repo-level line coverage percentage, read from the lcov coverage finding's
    ``parsed_value['total_pct']`` when present and the coverage artifact was
    usable. ``None`` when coverage was unavailable/stale/absent — NEVER coerced
    to ``0.0`` (a real 0% would be indistinguishable from "no data"; SAFE-04).

scan_cost_usd
    ``meta.total_cost_usd`` from the sidecar. ``None`` under ``--no-agent``
    (the fleet default in Plan 05) — render as ``n/a``, do not coerce to 0.

scan_seconds
    ``meta.wall_clock_seconds`` from the sidecar. ``None`` under ``--no-agent``
    — render as ``n/a``, do not coerce to 0.

----------------------------------------------------------------------------
FleetSnapshot — the top-level fleet artifact.
----------------------------------------------------------------------------

schema_version
    Literal ``'1'`` — this contract's OWN version, independent of
    ``ScanReport.schema_version`` (D-05-02). A consumer should switch on this
    to select a reader; a future additive change keeps ``'1'``, a
    rename/removal/retype bumps it.

generated_date
    The date the fleet sweep was run (ISO-8601 on dump).

sweep_root
    Absolute path of the directory swept (the ``repo-audit fleet <dir>`` argument).

total_repos
    Count of rows (ok + failed) in ``repos``.

total_blockers / total_critical
    Fleet-wide sums of blocker / critical findings across all ``'ok'`` rows
    (failed rows contribute nothing — they have no usable counts).

failed_count
    Number of ``'failed'`` rows.

total_cost_usd / sweep_seconds
    Fleet-wide aggregate cost / wall-clock for the sweep. ``None`` when the
    sweep ran ``--no-agent`` (no cost) or the caller did not supply a duration.
    Render as ``n/a``; never coerce ``None`` to 0.

repos
    The per-repo rows, in the deterministic discovery order (FLEET-01).
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.enums import Severity


class FleetRepoRow(BaseModel):
    """One repo's roll-up row. See module docstring for per-field semantics."""

    model_config = ConfigDict(extra="forbid")

    repo_slug: str
    repo_path: str
    status: Literal["ok", "failed"]
    error_reason: str | None = None
    commit_sha: str | None = None
    last_commit_iso: str | None = None
    scan_date: date | None = None
    # {dimension: {severity: count}} — only blocker/critical/major are counted.
    severity_by_dimension: dict[str, dict[str, int]] = Field(default_factory=dict)
    coverage_pct: float | None = None
    scan_cost_usd: float | None = None
    scan_seconds: float | None = None


class FleetSnapshot(BaseModel):
    """The fleet roll-up artifact. See module docstring for the contract."""

    model_config = ConfigDict(extra="forbid")

    # OWN version, independent of ScanReport's (D-05-02).
    schema_version: Literal["1"] = "1"
    generated_date: date
    sweep_root: str
    total_repos: int
    total_blockers: int
    total_critical: int
    failed_count: int
    total_cost_usd: float | None = None
    sweep_seconds: float | None = None
    repos: list[FleetRepoRow] = Field(default_factory=list)


# The actionable severity rungs the roll-up counts per dimension. Minor/info
# are excluded — the fleet view surfaces what demands attention (blockers,
# criticals) and the major backlog, not the long tail.
COUNTED_SEVERITIES: tuple[Severity, ...] = ("blocker", "critical", "major")
