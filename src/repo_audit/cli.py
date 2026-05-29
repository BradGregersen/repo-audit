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

from pathlib import Path

import typer

from repo_audit.detect.detector import detect_stacks
from repo_audit.doctor.self_test import run_secret_lint_self_test
from repo_audit.orchestration import run_scan

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
    # Plan 05-01: the entire pipeline body now lives in
    # orchestration.scan_runner.run_scan (single source of truth; repo-audit fleet
    # reuses the identical pipeline). This command is a thin wrapper that
    # parses Typer options, delegates, and reproduces the EXACT observable CLI
    # surface (exit codes, the INTEGRITY ALERT block, the agent-status line,
    # and the "Wrote ..." messages) from the returned ScanResult. Every
    # pipeline invariant (D-33, D-65, D-67, Pitfall 5/7) is preserved verbatim
    # inside run_scan.
    result = run_scan(
        Path(path).resolve(),
        no_agent=no_agent,
        refresh_coverage=refresh_coverage,
        agent_budget=agent_budget,
    )

    # render refused (secret-lint rc=2 / completion-honesty rc=3) → sidecar
    # NOT written; propagate the exit code unchanged. No "Wrote" / integrity /
    # agent-status surfaces on this path (mirrors pre-refactor early raise).
    if result.rc != 0:
        raise typer.Exit(code=result.rc)

    # D-33 post-flight integrity alert (does NOT fail the scan). run_scan
    # already appended the integrity note to scope_ledger.notes; the CLI owns
    # the user-facing stderr block.
    if result.offenders:
        typer.echo(
            "INTEGRITY ALERT: repo-audit scan modified files outside docs/state-reports/:",
            err=True,
        )
        for line in result.offenders:
            typer.echo(f"  {line}", err=True)
        typer.echo(
            "This is a bug; please file an issue with the offending file list above.",
            err=True,
        )

    # Phase 4 D-67: surface a non-ok agent fallback on stderr (the report is
    # still a clean deterministic-only report; the scan still exits 0).
    if result.agent_status is not None and result.agent_status != "ok":
        typer.echo(
            f"agent: {result.agent_status} (deterministic-only report shipped per D-67)",
            err=True,
        )

    typer.echo(f"Wrote {result.md_path}")
    typer.echo(f"Wrote {result.json_path}")


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
