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
from repo_audit.detect.detector import detect_stacks
from repo_audit.doctor.self_test import run_secret_lint_self_test
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.paths import state_report_paths
from repo_audit.meta.slug import repo_slug
from repo_audit.render.renderer import render_and_write
from repo_audit.schema.report import ReportMeta, ScanReport

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

    Writes only to ``{path}/docs/state-reports/{slug}-state-report-{date}.{md,json}``
    per REP-03. Secret-lint runs on both buffers before either touches disk
    (REP-05). On secret-lint refusal, the CLI propagates ``render_and_write``'s
    return code via ``typer.Exit`` -- no silent masking.
    """
    repo_path = Path(path).resolve()

    # Resolve metadata (D-12).
    slug = repo_slug(repo_path)
    try:
        commit_sha = head_sha(repo_path)
    except NotAGitRepo:
        # Edge: scanning a non-git directory. Treat as UNCOMMITTED for Phase 1
        # (Pitfall 3 generalization -- no git context still produces a report).
        commit_sha = UNCOMMITTED_MARKER
    scan_date = _date.today()
    detection = detect_stacks(repo_path)

    # Build the (empty-findings) ScanReport. Phase 1 ships zero collectors;
    # the renderer's D-09/D-10/D-11 pending markers communicate completion
    # honesty in the rendered output.
    meta = ReportMeta(
        repo_slug=slug,
        commit_sha=commit_sha,
        scan_date=scan_date,
        tool_version=__version__,
        detected_stacks=detection.stacks,
        baseline_run=True,  # Phase 1: always baseline (no prior sidecar)
    )
    scan_report = ScanReport(schema_version="1", meta=meta, findings=[])

    # Derive output paths (Pitfall 4: same-day collision -> -2/-3/...).
    md_path, json_path = state_report_paths(repo_path, scan_date)

    # Render + secret-lint + write. render_and_write handles all of
    # D-06 (refuse + non-zero), D-07 (lint BOTH buffers before write),
    # D-15 (mkdir post-lint). On non-zero, surface as the CLI's exit code.
    rc = render_and_write(scan_report, md_path, json_path)
    if rc != 0:
        raise typer.Exit(code=rc)
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
