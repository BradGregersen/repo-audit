"""Fleet sweep: sequential re-scan of every discovered repo (Plan 05-05).

``run_fleet(root, *, with_agent)`` is the orchestration core for ``repo-audit fleet``.
It discovers every immediate ``.git`` child under ``root`` (FLEET-01 / Plan 04
``discover_repos``), re-scans each one FRESH and SEQUENTIALLY (D-05-12 /
D-05-13), and aggregates the fresh per-repo JSON sidecars into a
``FleetSnapshot`` (Plan 04 ``aggregate``).

Economics (D-05-12): the sweep runs ``run_scan(..., no_agent=True)`` by DEFAULT
— fast, ~free, deterministic facts only. ``with_agent=True`` flips on per-repo
AI narration (``no_agent=False``). This avoids surprise cost×20 and the
large-repo agent-stage timeouts seen dogfooding Phase 4.

Freshness (D-05-13): every repo is re-scanned on every run; there is no
same-day sidecar reuse in v1. The sweep reflects current state.

Failure isolation (FLEET-04 / SC-5 / T-05-10): a per-repo scan that raises ANY
exception becomes a ``status='failed'`` dashboard row (via ``make_failed_row``)
and the sweep CONTINUES — one bad repo never aborts the whole fleet. A scan
that completes but whose render was refused (``rc != 0`` — secret-lint or
completion-honesty) is ALSO a failed row, not a raise. ``test_failure_does_not_abort``
proves this.

This module returns the ``FleetSnapshot`` ONLY — it performs no disk writes.
Rendering the dashboard + writing the JSON is the dashboard module's job
(``fleet.dashboard.render_fleet_dashboard``), orchestrated by the CLI. Keeping
``run_fleet`` write-free keeps the sweep cheaply testable without touching disk.
"""
from __future__ import annotations

import time
from datetime import date as _date
from pathlib import Path

from repo_audit.fleet.aggregate import (
    aggregate,
    build_repo_row,
    make_failed_row,
)
from repo_audit.fleet.discovery import discover_repos
from repo_audit.orchestration.scan_runner import run_scan
from repo_audit.schema.fleet import FleetRepoRow, FleetSnapshot


def run_fleet(root: Path, *, with_agent: bool = False) -> FleetSnapshot:
    """Sweep every immediate ``.git`` child of ``root`` and aggregate the result.

    Args:
        root: The sweep root directory (the ``repo-audit fleet <dir>`` argument).
        with_agent: When ``False`` (the default, D-05-12) each per-repo scan
            runs deterministic-only (``no_agent=True``) — fast, ~free, no AI
            cost. When ``True`` the per-repo scan runs the full agent loop
            (``no_agent=False``) for AI narration.

    Returns:
        A :class:`FleetSnapshot`. ``repos`` carries one row per discovered repo
        in deterministic discovery order; failed scans become ``status='failed'``
        rows with their ``error_reason`` and never abort the sweep (FLEET-04 /
        SC-5). When discovery finds zero repos the snapshot is empty
        (``total_repos == 0``) — the CLI surfaces the honest "no repos found"
        message (the sweep does NOT invent rows).

    The function performs NO disk writes; rendering + writing the dashboard and
    JSON happen downstream in ``fleet.dashboard.render_fleet_dashboard`` (called
    by the CLI). This keeps the sweep testable without filesystem side effects.
    """
    root = Path(root).resolve()
    sweep_start = time.perf_counter()

    discovery = discover_repos(root)
    rows: list[FleetRepoRow] = []

    for repo in discovery.repos:
        # FLEET-04 / SC-5 / T-05-10: the ENTIRE per-repo block is wrapped so
        # NOTHING (a run_scan exception, an OSError/PermissionError, a corrupt
        # sidecar path) can abort the sweep. A failure is a row, not a raise.
        try:
            result = run_scan(repo, no_agent=not with_agent)
            if result.rc != 0:
                # render refused (rc=2 secret-lint / rc=3 completion-honesty) —
                # no usable sidecar was written. Treat as a failed row; never
                # raise (D-05-10: a repo we couldn't fully scan is a triage row).
                rows.append(
                    make_failed_row(repo, f"scan refused (rc={result.rc})")
                )
            else:
                # build_repo_row reads the fresh JSON sidecar (JSON-only, SC-6);
                # it is itself failure-tolerant (corrupt sidecar -> failed row).
                rows.append(build_repo_row(repo, result.json_path))
        except Exception as exc:  # noqa: BLE001 — isolation is the contract.
            rows.append(make_failed_row(repo, repr(exc)))

    # Fleet-wide cost = sum of the per-row scan costs (None-safe). Under the
    # deterministic default every cost is None → the total stays None (NEVER
    # coerced to 0.0 — a real $0 must stay distinguishable from "no agent cost").
    costs = [r.scan_cost_usd for r in rows if r.scan_cost_usd is not None]
    total_cost_usd = sum(costs) if costs else None

    sweep_seconds = time.perf_counter() - sweep_start

    return aggregate(
        rows,
        sweep_root=str(root),
        generated_date=_date.today(),
        total_cost_usd=total_cost_usd,
        sweep_seconds=sweep_seconds,
    )
