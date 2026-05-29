"""Single-source-of-truth scan pipeline (RESEARCH Pattern 2).

`run_scan()` runs the ENTIRE single-repo pipeline that `cli.py::scan` used to
inline. Both ``repo-audit scan`` (cli.py) and ``repo-audit fleet`` (Plan 05) call this so
the pipeline is implemented exactly once — fleet must NOT re-implement the
pipeline nor call the Typer command directly (fragile: option defaults,
``typer.Exit``, stderr echoes).

The function returns a ``ScanResult`` (a plain data carrier) instead of calling
``typer.Exit`` / ``typer.echo``; the caller decides how to surface exit codes,
the integrity alert, the agent-status line, and the "Wrote ..." messages. This
keeps the pipeline free of CLI-presentation concerns while preserving every
documented invariant verbatim (D-33, D-65, D-67).

Read-only contract (REP-03 / Pitfall 7): the only legitimate write is the
sidecar pair under ``docs/state-reports/`` (via ``render_and_write``). The
post-flight ``diff_git_status`` integrity tripwire stays in ``run_scan`` and
must remain — it catches collector/tool BUGS that touch the target repo.

baseline_run (D-12, RESEARCH Pitfall 4): no longer hard-coded ``True``. It is
``True`` only when ``find_prior_sidecar`` finds no usable prior JSON sidecar
dated strictly before today; otherwise ``False`` (the first real trend scan
flips it off).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import date as _date
from pathlib import Path

from repo_audit import __version__
from repo_audit.adapters import run_adapters
from repo_audit.collectors import run_collectors
from repo_audit.detect.detector import detect_stacks
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.meta.paths import find_prior_sidecar, state_report_paths
from repo_audit.meta.slug import repo_slug
from repo_audit.orchestration.scope_ledger_builder import (
    auto_fill_ledger_gaps,
    build_scope_ledger,
)
from repo_audit.render.renderer import render_and_write
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.walker import build_repo_index


@dataclass
class ScanResult:
    """Data carrier returned by :func:`run_scan`.

    Fields:
        scan_report   -- the assembled, rendered ScanReport object
        md_path       -- path of the written markdown sidecar
        json_path     -- path of the written JSON sidecar
        rc            -- return code from render_and_write (0 ok / 2 secret-lint
                         / 3 completion-honesty). When rc != 0 the sidecar pair
                         was NOT written and md_path/json_path are the intended
                         (unwritten) targets; the caller raises typer.Exit(rc).
        agent_status  -- meta.agent_status after the run (None under --no-agent,
                         'ok' on success, a D-67 fallback reason otherwise).
        offenders     -- post-flight integrity offenders (files modified outside
                         docs/state-reports/). Empty on a clean read-only run.
                         The caller echoes the INTEGRITY ALERT block from this.
        prior_sidecar -- the most-recent prior JSON sidecar before today (or
                         None for a baseline run). Plan 02/03 consume this for
                         delta computation; this plan just uses its presence to
                         drive baseline_run.
    """

    scan_report: ScanReport
    md_path: Path
    json_path: Path
    rc: int
    agent_status: str | None
    offenders: list[str] = field(default_factory=list)
    prior_sidecar: Path | None = None


def _maybe_refresh_coverage(repo_path: Path, findings: list) -> list:
    """Plan 03-05 Decision C sub-steps C + D: refresh-coverage wiring.

    Called when the user passes ``--refresh-coverage`` to ``repo-audit scan``.
    Inspects the merged findings list for a prior ``coverage_unavailable``
    Finding emitted by the lcov parser's import-only pass; if found,
    invokes plan 03-06's ``refresh_coverage`` runner and branches:

      * RefreshResult.status == 'ok' (sub-step C):
        Re-invokes ``parse_from_repo(repo_path)`` to obtain the fresh
        aggregate Finding; REPLACES the prior unavailable Finding with the
        fresh aggregate via a list comprehension that preserves the
        relative order of all other findings.

      * RefreshResult.status in {'failed', 'timeout'} (sub-step D):
        Calls plan 03-03's ``_refresh_failed_finding`` helper and APPENDS
        the returned ``evidence_type='failed'`` Finding to the merged list.
        Does NOT remove the prior unavailable Finding — the report shows
        both "no fresh artifact" AND "we tried; here's why it failed."

      * RefreshResult.status == 'skipped' or no prior unavailable Finding:
        no-op; returns the input list unchanged.

    Imports inside this function (rather than at module top) so the
    --refresh-coverage flag is the only call site that pulls in the
    refresh runner + lcov re-invoke helpers. Module-load cost stays
    bounded by the regular adapter-package import already at the top.
    """
    # Locate the previous 'unavailable' Finding emitted by the first lcov
    # parser pass (plan 03-03 contract: source_tool='lcov' AND
    # rule_id='coverage_unavailable').
    prior_unavailable = [
        f for f in findings
        if getattr(f, "source_tool", "") == "lcov"
        and getattr(f, "rule_id", "") == "coverage_unavailable"
    ]
    if not prior_unavailable:
        # Coverage was fresh on the first pass; nothing to refresh.
        return findings

    import os
    from repo_audit.adapters.typescript import CONFIG as _TS_CONFIG
    from repo_audit.adapters.typescript.parsers.lcov import (
        _refresh_failed_finding,
        parse_from_repo as _parse_lcov_from_repo,
    )
    from repo_audit.adapters.typescript.refresh import (
        refresh_coverage as _refresh_runner,
    )

    refresh_cfg = _TS_CONFIG.get("tools", {}).get("coverage_refresh", {})
    refresh_result = _refresh_runner(
        repo_root=repo_path,
        cfg=refresh_cfg,
        env=dict(os.environ),  # plan 03-06 applies the secret-scrub
    )

    if refresh_result.status == "ok":
        # Sub-step C: re-invoke lcov parser; replace the unavailable
        # Finding with the fresh aggregate (preserve order).
        fresh_findings = _parse_lcov_from_repo(repo_path)
        fresh_aggregate = next(
            (f for f in fresh_findings if getattr(f, "rule_id", "") == "coverage_summary"),
            None,
        )
        if fresh_aggregate is not None:
            return [
                fresh_aggregate if (
                    getattr(f, "source_tool", "") == "lcov"
                    and getattr(f, "rule_id", "") == "coverage_unavailable"
                ) else f
                for f in findings
            ]
        # Fresh parse did not produce an aggregate (artifact still missing
        # despite ok status — unlikely but defensive); fall through and
        # leave the unavailable Finding in place.
        return findings

    if refresh_result.status in {"failed", "timeout"}:
        # Sub-step D: synthesize a 'failed' Finding; do NOT remove the
        # prior unavailable Finding — both surface in the report.
        failed_finding = _refresh_failed_finding(
            refresh_result,
            runner_command=refresh_result.runner_command,
        )
        return findings + [failed_finding]

    # status == 'skipped' → no-op (refresh chose not to run).
    return findings


def run_scan(
    repo_path: Path,
    *,
    no_agent: bool = False,
    refresh_coverage: bool = False,
    agent_budget: int | None = None,
) -> ScanResult:
    """Run the full single-repo scan pipeline and return a :class:`ScanResult`.

    This is the single source of truth for the scan pipeline. ``repo-audit scan``
    (cli.py) and ``repo-audit fleet`` (Plan 05) both call it. It performs NO
    CLI-presentation side effects (no ``typer.echo`` / ``typer.Exit``); the
    caller surfaces rc, integrity offenders, agent status, and "Wrote ..."
    lines from the returned ``ScanResult``.

    Pipeline (every step preserved verbatim from the original cli.py::scan):
        1. overall_start timer (Phase 4 wall-clock)
        2. snapshot_git_status(repo) — BEFORE collectors (D-33 baseline)
        3. metadata: slug / head_sha / scan_date / detect_stacks
        4. build_repo_index(repo) — single shared walker (D-26)
        5. run_collectors(repo, walker.index) — sequential (D-24)
        5.5 run_adapters(repo, detection) — Phase 3 stack-adapter dispatch
        6. merge collector + adapter findings
        6.5 _maybe_refresh_coverage(...) when refresh_coverage (Decision C)
        7. build_scope_ledger(...) — REP-04 / D-30
        8. partial determination — D-31
        8.5 find_prior_sidecar → baseline_run conditional (Plan 05-01)
        9. ReportMeta assembly
        9.5 agent_budget override (AGENT-05 / D-65)
        10. run_agent_session (unless no_agent) — D-53 / D-67
        10.5 auto_fill_ledger_gaps — AGENT-07 / D-60
        11. ScanReport assembly
        12. state_report_paths + render_and_write (D-07 / D-32)
        13. meta.wall_clock_seconds overwrite AFTER render (Pitfall 5)
        14. post-flight diff_git_status integrity tripwire (D-33 / Pitfall 7)

    Exit codes (carried on ScanResult.rc): 0 success / 2 secret-lint / 3
    completion-honesty.
    """
    repo_path = Path(repo_path).resolve()
    overall_start = time.perf_counter()  # Phase 4 — overall arch-scan wall-clock

    # D-33 pre-flight snapshot (must happen BEFORE any collector reads).
    pre_status = snapshot_git_status(repo_path)

    # Metadata (D-12).
    slug = repo_slug(repo_path)
    try:
        commit_sha = head_sha(repo_path)
    except NotAGitRepo:
        commit_sha = UNCOMMITTED_MARKER
    scan_date = _date.today()
    detection = detect_stacks(repo_path)

    # D-26 walker — single in-memory index, fed to every collector.
    walker_result = build_repo_index(repo_path)

    # D-24 sequential collector orchestration.
    collector_results = run_collectors(repo_path, walker_result.index)

    # Phase 3 (Plan 03-05): adapter dispatch between collectors and ledger.
    # Called via the module attribute so it stays patchable in tests.
    adapter_results = run_adapters(repo_path, detection)

    # Aggregate findings across collectors + adapters (sequential preserves
    # ledger order). Built BEFORE the refresh sub-steps below so the
    # sub-steps can rewrite/extend this list in place.
    findings = (
        [f for r in collector_results for f in r.findings]
        + [f for r in adapter_results for f in r.findings]
    )

    # Sub-step C + D: --refresh-coverage opt-in wiring (D-41' / Decision A).
    # Runs BEFORE build_scope_ledger so the ledger reflects the
    # post-refresh findings state. Sub-step C replaces the lcov
    # 'coverage_unavailable' Finding with the fresh aggregate on refresh
    # success; sub-step D appends a 'coverage_refresh_failed' Finding on
    # refresh failure (does NOT remove the unavailable Finding — both
    # surface so the reader sees "no fresh artifact" AND "we tried; here's
    # why it failed").
    if refresh_coverage:
        findings = _maybe_refresh_coverage(repo_path, findings)

    # D-30 scope ledger assembly (Phase 3: adapter_results folded).
    scope_ledger = build_scope_ledger(
        walker_result, collector_results,
        repo_path=repo_path,
        adapter_results=adapter_results,
    )

    # D-31 partial-scan determination (Phase 3: adapter status considered).
    partial = (
        walker_result.status != "ok"
        or any(r.status != "ok" for r in collector_results)
        or any(r.status != "ok" for r in adapter_results)
    )

    # Plan 05-01 / TREND-01: baseline_run is conditional on a prior sidecar.
    # find_prior_sidecar returns the most-recent JSON sidecar with
    # meta.scan_date strictly before today (or None — same-day re-run, no
    # prior dir, no JSON, all-corrupt → baseline). The first real trend scan
    # flips baseline_run off (RESEARCH Pitfall 4 — was hard-coded True).
    prior_sidecar = find_prior_sidecar(repo_path, scan_date)

    # Assemble ScanReport.
    meta = ReportMeta(
        repo_slug=slug,
        commit_sha=commit_sha,
        scan_date=scan_date,
        tool_version=__version__,
        detected_stacks=detection.stacks,
        baseline_run=(prior_sidecar is None),  # Plan 05-01: conditional (TREND-01)
        partial=partial,
    )

    # Phase 4 NEW: AGENT-05 budget override (D-65) — one-shot scan override.
    # Mutates the AGENT_DEFAULTS dict the agent loop reads via get_threshold();
    # process-local + benign (each Typer invocation is a fresh CLI context).
    if agent_budget is not None:
        from repo_audit.agent.constants import AGENT_DEFAULTS
        AGENT_DEFAULTS["agent.max_tokens_per_scan"] = int(agent_budget)

    # Phase 4 NEW: agent session (D-53, D-65, D-67, D-68).
    # Skipped under --no-agent for debugging the deterministic pipeline.
    # Returns (AgentScanReport | None, mutated_meta); on failure agent_output
    # is None and meta.agent_status carries the reason (D-67 exit-0 contract).
    # Called via the module attribute so the loop is patchable in tests and
    # session.py (which imports the SDK) is only pulled in when needed.
    agent_output = None
    if not no_agent:
        from repo_audit.agent import session as _agent_session
        agent_output, meta = asyncio.run(_agent_session.run_agent_session(
            findings=findings,
            scope_ledger=scope_ledger,
            detection=detection,
            meta=meta,
        ))

    # Phase 4 NEW: AGENT-07 post-flight ledger-gap auto-fill (D-60).
    # Under D-57 read-only tools this is defense in depth — the agent path
    # cannot create gaps; this catches collector-execution bugs and primes
    # future action-tool semantics.
    findings, scope_ledger = auto_fill_ledger_gaps(
        findings, scope_ledger, detection,
        repo_path=repo_path,
        walker_index=walker_result.index,
    )

    scan_report = ScanReport(
        schema_version="1",
        meta=meta,
        findings=findings,
        scope_ledger=scope_ledger,
    )

    # Output paths (Pitfall 4 collision-safe per Plan 02-01a paths.py fix).
    md_path, json_path = state_report_paths(repo_path, scan_date)

    # Render + secret-lint + completion-honesty + faithfulness + write.
    # agent_output is None on --no-agent + every D-67 fallback → the renderer
    # takes the deterministic-only path (Plan 04-08).
    rc = render_and_write(scan_report, md_path, json_path, agent_output=agent_output)
    # Phase 4: overwrite wall_clock_seconds with the overall arch-scan duration
    # (RESEARCH Open Question 2 — caller-overrides-session). This is the
    # user-facing total; session.py's agent-only measurement is superseded.
    # MUST happen AFTER render_and_write returns (RESEARCH Pitfall 5).
    meta.wall_clock_seconds = time.perf_counter() - overall_start
    if rc != 0:
        # render refused (secret-lint / completion-honesty); sidecar NOT
        # written. Caller raises typer.Exit(rc). No post-flight check needed
        # (nothing was written).
        return ScanResult(
            scan_report=scan_report,
            md_path=md_path,
            json_path=json_path,
            rc=rc,
            agent_status=meta.agent_status,
            offenders=[],
            prior_sidecar=prior_sidecar,
        )

    # D-33 post-flight integrity check (does NOT fail the scan).
    post_status = snapshot_git_status(repo_path)
    offenders = diff_git_status(pre_status, post_status)
    if offenders:
        # D-33 honesty contract: append integrity entry to in-memory
        # scope_ledger.notes so a follow-up tool inspection of the
        # ScanReport object surfaces the alert. The on-disk JSON sidecar
        # was already written before this check (the post-flight is a
        # tripwire for tool BUGS, not a routine ledger entry); future
        # Phase 5 can revisit if a "re-render with integrity row" gate
        # is wanted. The stderr INTEGRITY ALERT block is emitted by the
        # caller from ScanResult.offenders.
        integrity_note = (
            f"Integrity alert: {len(offenders)} unexpected "
            f"file(s) modified outside docs/state-reports/"
        )
        if scan_report.scope_ledger.notes:
            scan_report.scope_ledger.notes += "; " + integrity_note
        else:
            scan_report.scope_ledger.notes = integrity_note

    return ScanResult(
        scan_report=scan_report,
        md_path=md_path,
        json_path=json_path,
        rc=rc,
        agent_status=meta.agent_status,
        offenders=offenders,
        prior_sidecar=prior_sidecar,
    )
