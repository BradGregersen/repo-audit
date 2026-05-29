"""Typer CLI app for repo-audit.

Entry point for ``[project.scripts] repo-audit = "repo_audit.cli:app"``.
After ``uv tool install --editable .``, the shell command ``arch`` invokes
this module's ``app`` (CLI-01).

Subcommands:
    repo-audit scan [PATH]     -- emit state report for a repo (CLI-02 / SC-3)
    repo-audit detect [PATH]   -- show auto-detected stack(s) (CLI-04 / SC-2)
    repo-audit fleet DIR       -- Phase 5 stub (exits with explanation)

Root flags:
    --doctor --self-test-secret-lint   -- runtime proof of REP-05 (D-08)
    --doctor (alone)                   -- placeholder; full --doctor is Phase 7

Read-only contract (REP-03):
    ``scan`` writes ONLY to ``{path}/docs/state-reports/{slug}-state-report-{date}.{md,json}``.
    All disk I/O is routed through ``render_and_write`` (single chokepoint,
    Pitfall 2). The CLI contains zero ``write_text`` / ``mkdir`` calls of
    its own and no ``subprocess`` calls.
"""
from __future__ import annotations

import asyncio
import time
from datetime import date as _date
from pathlib import Path

import typer

from repo_audit import __version__
from repo_audit.adapters import run_adapters
# Phase 3 side-effect import: bringing this module in triggers
# ``@register_adapter("typescript-node")`` so ``run_adapters`` actually
# dispatches the TS adapter. Closes DI-03-03-01 (integration test had
# no registration trigger).
from repo_audit.adapters import typescript as _ts_adapter  # noqa: F401
from repo_audit.collectors import run_collectors
from repo_audit.detect.detector import detect_stacks
from repo_audit.doctor.self_test import run_secret_lint_self_test
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.meta.paths import state_report_paths
from repo_audit.meta.slug import repo_slug
from repo_audit.orchestration import auto_fill_ledger_gaps, build_scope_ledger
from repo_audit.render.renderer import render_and_write
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.walker import build_repo_index

# D-13: bare ``arch`` prints help (no_args_is_help=True is Typer's idiom).
# pretty_exceptions_show_locals=False hardens tracebacks against leaking
# in-flight buffers if the agent ever exceptions out mid-render.
app = typer.Typer(
    name="arch",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
    help="Polyglot repo-health audit CLI.",
)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    doctor: bool = typer.Option(
        False,
        "--doctor",
        help="Health-check mode (full diagnostic ships in Phase 7).",
    ),
    self_test_secret_lint: bool = typer.Option(
        False,
        "--self-test-secret-lint",
        help=(
            "Verify the renderer's secret-lint catches a synthetic secret "
            "(D-08 / REP-05)."
        ),
    ),
) -> None:
    """Polyglot repo-health audit CLI."""
    # D-08: narrow Phase 1 --doctor path.
    if doctor and self_test_secret_lint:
        raise typer.Exit(code=run_secret_lint_self_test())
    if doctor:
        typer.echo(
            "Full --doctor lands in Phase 7. Only --self-test-secret-lint "
            "is wired in Phase 1.",
            err=True,
        )
        raise typer.Exit(code=2)
    # Otherwise fall through; Typer's no_args_is_help handles bare ``arch``.


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


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the repo to scan (defaults to cwd, D-14).",
    ),
    refresh_coverage: bool = typer.Option(
        False,
        "--refresh-coverage",
        help=(
            "Invoke the configured test runner to produce fresh coverage "
            "when coverage/lcov.info is missing or stale "
            "(default: off; see adapter.yaml coverage_refresh.mode)."
        ),
    ),
    no_agent: bool = typer.Option(
        False,
        "--no-agent",
        help=(
            "Skip the Claude Agent SDK loop entirely; produce a deterministic-"
            "only report. Useful for debugging the deterministic pipeline "
            "without paying agent cost or under offline conditions."
        ),
    ),
    agent_budget: int | None = typer.Option(
        None,
        "--agent-budget",
        help=(
            "Override agent.max_tokens_per_scan for this scan (default: "
            "150,000). The ENFORCEABLE cap under Max OAuth; the loop "
            "disconnects when running tokens cross this threshold."
        ),
    ),
) -> None:
    """Scan a repo and emit a state report + JSON sidecar (CLI-02 / SC-3).

    Phase 3 pipeline:
        1. snapshot_git_status(repo) — BEFORE collectors (D-33 baseline)
        2. build_repo_index(repo) — single shared walker (D-26)
        3. run_collectors(repo, walker.index) — sequential per registry order (D-24)
        3.5 run_adapters(repo, detection) — NEW Phase 3 stack-adapter dispatch
            (currently TypeScript only; Phase 6 adds Python + Kotlin).
        4. build_scope_ledger(walker, collectors, adapter_results=adapters) —
           REP-04 / D-30 extended to fold AdapterResult rows.
        5. render_and_write — secret-lint + completion-honesty + write (D-07, D-32)
        6. snapshot_git_status + diff_git_status — post-flight integrity (D-33)
           (does NOT fail the scan; emits stderr warning on offenders)

    When ``--refresh-coverage`` is set, the TypeScript adapter invokes the
    test runner declared in adapter.yaml (default: ``npm test``) to produce
    ``coverage/lcov.info`` when the artifact is missing or stale; default is
    off (import-only). On success, the previous unavailable coverage Finding
    is REPLACED by the fresh aggregate Finding (Decision C sub-step C). On
    runner failure, a separate ``evidence_type='failed'`` Finding is APPENDED
    alongside the unavailable Finding (Decision C sub-step D). See plan
    03-06's refresh.py for the runner-invocation contract
    (T-03-refresh-injection, T-03-refresh-dos, T-03-refresh-env-leak).

    Phase 4 extensions (additive — every Phase 3 invariant above is preserved):
        4.5 run_agent_session(...) — the single ClaudeSDKClient loop (D-53),
            invoked BETWEEN build_scope_ledger and render_and_write. Skipped
            entirely under ``--no-agent`` (deterministic-only report).
        4.6 auto_fill_ledger_gaps(...) — D-60 post-flight ledger-completeness
            backstop (AGENT-07), run AFTER the agent session and BEFORE render.
        ``--agent-budget N`` overrides agent.max_tokens_per_scan for this scan
        (AGENT-05 / D-65). ``meta.wall_clock_seconds`` is overwritten with the
        overall arch-scan duration after render_and_write returns (RESEARCH
        Open Question 2).

    D-67 honesty contract: every agent fallback mode (auth missing, network,
    cost-capped, SDK exception) still ships a deterministic report and exits 0;
    the agent_status is surfaced on stderr.

    Exit codes:
        0 — success (incl. every D-67 agent fallback mode)
        2 — secret-lint refused (REP-05 / D-06)
        3 — completion-honesty refused (SAFE-08 / D-32)
    """
    repo_path = Path(path).resolve()
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
    # The TS adapter package is imported at module-load (above) so
    # ``@register_adapter("typescript-node")`` has already fired by here.
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

    # Assemble ScanReport.
    meta = ReportMeta(
        repo_slug=slug,
        commit_sha=commit_sha,
        scan_date=scan_date,
        tool_version=__version__,
        detected_stacks=detection.stacks,
        baseline_run=True,  # Phase 1 + 2: always baseline (no prior sidecar)
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
    meta.wall_clock_seconds = time.perf_counter() - overall_start
    if rc != 0:
        raise typer.Exit(code=rc)

    # D-33 post-flight integrity check (does NOT fail the scan).
    post_status = snapshot_git_status(repo_path)
    offenders = diff_git_status(pre_status, post_status)
    if offenders:
        # Stderr warning (user-facing surface).
        typer.echo(
            "INTEGRITY ALERT: repo-audit scan modified files outside docs/state-reports/:",
            err=True,
        )
        for line in offenders:
            typer.echo(f"  {line}", err=True)
        typer.echo(
            "This is a bug; please file an issue with the offending file list above.",
            err=True,
        )
        # D-33 honesty contract: append integrity entry to in-memory
        # scope_ledger.notes so a follow-up tool inspection of the
        # ScanReport object surfaces the alert. The on-disk JSON sidecar
        # was already written before this check (the post-flight is a
        # tripwire for tool BUGS, not a routine ledger entry); future
        # Phase 5 can revisit if a "re-render with integrity row" gate
        # is wanted.
        integrity_note = (
            f"Integrity alert: {len(offenders)} unexpected "
            f"file(s) modified outside docs/state-reports/"
        )
        if scan_report.scope_ledger.notes:
            scan_report.scope_ledger.notes += "; " + integrity_note
        else:
            scan_report.scope_ledger.notes = integrity_note

    # Phase 4 D-67: surface a non-ok agent fallback on stderr (the report is
    # still a clean deterministic-only report; the scan still exits 0).
    if meta.agent_status is not None and meta.agent_status != "ok":
        typer.echo(
            f"agent: {meta.agent_status} (deterministic-only report shipped per D-67)",
            err=True,
        )

    typer.echo(f"Wrote {md_path}")
    typer.echo(f"Wrote {json_path}")


@app.command()
def detect(
    path: Path = typer.Argument(Path("."), help="Path to the repo to inspect."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of a human-readable table.",
    ),
) -> None:
    """Show auto-detected stack(s) without running a full scan (CLI-04 / SC-2)."""
    result = detect_stacks(Path(path).resolve())
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
        return
    if not result.stacks:
        typer.echo(
            "No stacks detected -- universal collectors will still run in Phase 2+."
        )
        return
    # Plain-text human table.
    typer.echo(f"Detected {len(result.stacks)} stack(s):")
    for s in result.stacks:
        typer.echo(
            f"  - {s.stack}  (root: {s.root_dir}, confidence: {s.confidence:.2f})"
        )


@app.command()
def fleet(
    directory: Path = typer.Argument(..., help="Directory containing repos to sweep."),
) -> None:
    """Sweep a directory of repos (Phase 5 -- stub in Phase 1)."""
    typer.echo(
        "repo-audit fleet lands in Phase 5 (Trend Memory & Fleet Roll-up) -- "
        "not implemented yet.",
        err=True,
    )
    raise typer.Exit(code=2)
