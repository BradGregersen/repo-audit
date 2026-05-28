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

from datetime import date as _date
from pathlib import Path

import typer

from repo_audit import __version__
from repo_audit.collectors import run_collectors
from repo_audit.detect.detector import detect_stacks
from repo_audit.doctor.self_test import run_secret_lint_self_test
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.meta.paths import state_report_paths
from repo_audit.meta.slug import repo_slug
from repo_audit.orchestration import build_scope_ledger
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


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the repo to scan (defaults to cwd, D-14).",
    ),
) -> None:
    """Scan a repo and emit a state report + JSON sidecar (CLI-02 / SC-3).

    Phase 2 pipeline:
        1. snapshot_git_status(repo) — BEFORE collectors (D-33 baseline)
        2. build_repo_index(repo) — single shared walker (D-26)
        3. run_collectors(repo, walker.index) — sequential per registry order (D-24)
        4. build_scope_ledger(walker, results) — REP-04 / D-30
        5. render_and_write — secret-lint + completion-honesty + write (D-07, D-32)
        6. snapshot_git_status + diff_git_status — post-flight integrity (D-33)
           (does NOT fail the scan; emits stderr warning on offenders)

    Exit codes:
        0 — success
        2 — secret-lint refused (REP-05 / D-06)
        3 — completion-honesty refused (SAFE-08 / D-32)
    """
    repo_path = Path(path).resolve()

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

    # D-30 scope ledger assembly.
    scope_ledger = build_scope_ledger(
        walker_result, collector_results, repo_path=repo_path,
    )

    # D-31 partial-scan determination.
    partial = (
        walker_result.status != "ok"
        or any(r.status != "ok" for r in collector_results)
    )

    # Aggregate findings across collectors (sequential preserves ledger order).
    findings = [f for r in collector_results for f in r.findings]

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
    scan_report = ScanReport(
        schema_version="1",
        meta=meta,
        findings=findings,
        scope_ledger=scope_ledger,
    )

    # Output paths (Pitfall 4 collision-safe per Plan 02-01a paths.py fix).
    md_path, json_path = state_report_paths(repo_path, scan_date)

    # Render + secret-lint + completion-honesty + write.
    rc = render_and_write(scan_report, md_path, json_path)
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
