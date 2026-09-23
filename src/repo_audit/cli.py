"""Typer CLI app for repo-audit.

Entry point for ``[project.scripts] repo-audit = "repo_audit.cli:app"``.
After ``uv tool install --editable .``, the shell command ``repo-audit``
invokes this module's ``app``.

Subcommands:
    repo-audit scan [PATH]     -- write a state report for one repo
    repo-audit detect [PATH]   -- show the auto-detected stack(s)
    repo-audit fleet DIR       -- sweep child repos into a fleet dashboard
    repo-audit issues [PATH]   -- file confirmed findings as GitHub issues (gated)

Root flags:
    --doctor --self-test-secret-lint   -- prove the renderer's secret-lint fires
    --doctor (alone)                   -- not yet implemented; exits 2

Report location:
    Inside the scanned repo, ``scan`` writes only to
    ``{path}/docs/state-reports/{slug}-state-report-{date}.{md,json}``. That
    write is routed through ``render_and_write`` (a single chokepoint). The
    CLI itself contains no ``write_text`` / ``mkdir`` / ``subprocess`` calls.
"""
from __future__ import annotations

from pathlib import Path

import typer

from repo_audit.detect.detector import detect_stacks
from repo_audit.doctor.self_test import run_secret_lint_self_test

# Per-adapter side-effect imports: importing the adapter package triggers its
# @register_adapter(...) so the detector's stack dispatch + the scope ledger see
# it (the same one-line pattern the typescript adapter uses).
import repo_audit.adapters.architecture  # noqa: F401, E402
import repo_audit.adapters.mobile  # noqa: F401, E402
import repo_audit.adapters.sast  # noqa: F401, E402
import repo_audit.adapters.supabase  # noqa: F401, E402
from repo_audit.fleet.dashboard import render_fleet_dashboard
from repo_audit.fleet.sweep import run_fleet
from repo_audit.issues import run_issues
from repo_audit.meta.paths import fleet_report_paths
from repo_audit.orchestration import run_scan

# Bare ``repo-audit`` prints help (no_args_is_help=True is Typer's idiom).
# pretty_exceptions_show_locals=False hardens tracebacks against leaking
# in-flight buffers if the agent ever exceptions out mid-render.
app = typer.Typer(
    name="repo-audit",
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
        help=(
            "Health-check mode. Only --doctor --self-test-secret-lint is "
            "implemented; --doctor on its own exits 2."
        ),
    ),
    self_test_secret_lint: bool = typer.Option(
        False,
        "--self-test-secret-lint",
        help=(
            "Verify the renderer's secret-lint catches a synthetic secret."
        ),
    ),
) -> None:
    """Polyglot repo-health audit CLI."""
    # Only the secret-lint self-test is implemented under --doctor.
    if doctor and self_test_secret_lint:
        raise typer.Exit(code=run_secret_lint_self_test())
    if doctor:
        typer.echo(
            "--doctor on its own is not yet implemented; run "
            "--doctor --self-test-secret-lint.",
            err=True,
        )
        raise typer.Exit(code=2)
    # Otherwise fall through; Typer's no_args_is_help handles bare ``repo-audit``.


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the repo to scan. Default: the current directory.",
    ),
    refresh_coverage: bool = typer.Option(
        False,
        "--refresh-coverage",
        help=(
            "Run the repo's configured test runner to produce fresh coverage "
            "when coverage/lcov.info is missing or stale. Default: off "
            "(existing coverage artifacts are only imported)."
        ),
    ),
    refresh_vuln_db: bool = typer.Option(
        False,
        "--refresh-vuln-db",
        help=(
            "Download a fresh vulnerability-database snapshot (osv + grype) "
            "before scanning. Default: off. Without it the local snapshot is "
            "only downloaded on the first scan and otherwise stays pinned."
        ),
    ),
    no_agent: bool = typer.Option(
        False,
        "--no-agent",
        help=(
            "Skip the Claude agent entirely and produce a deterministic-only "
            "report. Useful for offline runs or to avoid agent cost."
        ),
    ),
    agent_budget: int | None = typer.Option(
        None,
        "--agent-budget",
        help=(
            "Override the per-scan agent token cap (default: 150,000). The "
            "agent loop stops when its token usage crosses this cap."
        ),
    ),
    uncapped: bool = typer.Option(
        False,
        "--uncapped",
        help=(
            "Remove every agent and critic budget cap (tokens, turns, cost, "
            "and the critic's wall-clock cap) for this run only, for a "
            "thorough run on a large repo. Overrides --agent-budget; no "
            "effect with --no-agent. Default: off."
        ),
    ),
    rls_runtime: bool = typer.Option(
        False,
        "--rls-runtime",
        help=(
            "Run the two-account runtime RLS enforcement test against the LIVE "
            "Supabase project. Requires the six AUDIT_TEST_USER_* and "
            "EXPO_PUBLIC_SUPABASE_* environment variables. Default: off; "
            "credentials alone never trigger it (static splinter checks always run)."
        ),
    ),
    rls_pgrls: bool = typer.Option(
        False,
        "--rls-pgrls",
        help=(
            "Also run the pgrls RLS linter (beta) on top of the always-on "
            "splinter checks. Default: off."
        ),
    ),
    mobsf: bool = typer.Option(
        False,
        "--mobsf",
        help=(
            "Run a static MobSF scan of an existing APK in Docker. Default: "
            "off. With no APK present, add --mobsf-build to build one or --apk "
            "to point at one. mobsfscan and the bundled-secrets check run by "
            "default without this flag."
        ),
    ),
    mobsf_build: bool = typer.Option(
        False,
        "--mobsf-build",
        help=(
            "Build a debug APK with Gradle (assembleDebug) in a throwaway copy "
            "of the repo, for --mobsf to scan when no APK exists. Default: off."
        ),
    ),
    apk: Path | None = typer.Option(
        None,
        "--apk",
        help="Explicit path to a debug APK for --mobsf to scan.",
    ),
    no_sast: bool = typer.Option(
        False,
        "--no-sast",
        help=(
            "Skip the Semgrep SAST pass. SAST is on by default, fetches Semgrep "
            "rule packs over the network, and reports unavailable when semgrep "
            "or the network is absent."
        ),
    ),
    mutation: bool = typer.Option(
        False,
        "--mutation",
        help=(
            "Run StrykerJS mutation testing (JS/TS). Slow; capped at 30 "
            "minutes. Default: off, and never run by fleet."
        ),
    ),
    typed_detekt: bool = typer.Option(
        True,
        "--typed-detekt/--no-typed-detekt",
        help=(
            "Run detekt with type resolution by building the repo's Kotlin with "
            "its own ./gradlew in a throwaway copy; falls back to standalone "
            "detekt if the build fails. Default: on."
        ),
    ),
    qd_build: bool = typer.Option(
        False,
        "--qd-build",
        help=(
            "Build a React Native production bundle with Metro in a throwaway "
            "copy to measure bundle size. Default: off, and never run by "
            "fleet. Without it, bundle size is read only from an existing "
            "build artifact."
        ),
    ),
    e2e: bool = typer.Option(
        False,
        "--e2e",
        help=(
            "Run the repo's existing E2E suite (Detox/Maestro/Playwright) if one "
            "exists and its infrastructure is available. Never writes tests. "
            "Default: off, and never run by fleet."
        ),
    ),
    fuzz: bool = typer.Option(
        False,
        "--fuzz",
        help=(
            "Run the repo's existing fuzz suites (atheris/jazzer) under a short "
            "time budget. Never writes fuzz targets. Default: off."
        ),
    ),
    epss: bool = typer.Option(
        False,
        "--epss",
        help=(
            "Fetch live EPSS exploit-probability scores from FIRST over the "
            "network. Default: off (EPSS is reported unavailable and does not "
            "affect ranking). Never run by fleet."
        ),
    ),
    refresh_kev: bool = typer.Option(
        False,
        "--refresh-kev",
        help=(
            "Download a fresh CISA Known Exploited Vulnerabilities snapshot "
            "before scanning. Default: off; scans use the snapshot bundled "
            "with repo-audit and make no network request for it."
        ),
    ),
) -> None:
    """Scan a repo and write a state report plus a JSON sidecar.

    Detects the repo's stacks, runs the universal collectors and the matching
    stack adapters, optionally lets a Claude agent write narrative prose over
    the collected evidence, and writes the report pair to
    ``PATH/docs/state-reports/``. Nothing else inside the scanned repo is
    modified; a post-scan git-status check warns if anything else changed.

    Every agent failure (missing auth, network, budget exhausted, SDK error)
    still produces a deterministic report and exits 0; the agent status is
    printed on stderr.

    Exit codes:
        0 — success (including every agent fallback)
        2 — secret-lint refused to write the report
        3 — completion-honesty check refused to write the report
        4 — --refresh-kev download failed
    """
    # --refresh-kev is the only path that advances the bundled CISA KEV
    # snapshot. It runs before the scan; the default scan path never re-fetches.
    # A fetch failure surfaces on stderr and aborts (rc=4) rather than silently
    # scanning against a stale snapshot.
    if refresh_kev:
        from repo_audit.synthesis.kev import refresh_kev_snapshot

        try:
            sha = refresh_kev_snapshot()
            typer.echo(f"Refreshed KEV snapshot (sha256: {sha})")
        except Exception as exc:  # noqa: BLE001 — explicit step: surface + abort
            typer.echo(f"--refresh-kev failed: {exc}", err=True)
            raise typer.Exit(code=4) from exc

    # The entire pipeline body lives in orchestration.scan_runner.run_scan
    # (single source of truth; repo-audit fleet reuses the identical pipeline).
    # This command is a thin wrapper that parses Typer options, delegates, and
    # reproduces the observable CLI surface (exit codes, the INTEGRITY ALERT
    # block, the agent-status line, and the "Wrote ..." messages) from the
    # returned ScanResult.
    result = run_scan(
        Path(path).resolve(),
        no_agent=no_agent,
        refresh_coverage=refresh_coverage,
        refresh_vuln_db=refresh_vuln_db,
        agent_budget=agent_budget,
        uncapped=uncapped,
        rls_runtime=rls_runtime,
        rls_pgrls=rls_pgrls,
        mobsf=mobsf,
        mobsf_build=mobsf_build,
        apk=apk,
        sast=not no_sast,
        mutation=mutation,
        typed_detekt=typed_detekt,
        qd_build=qd_build,
        e2e=e2e,
        fuzz=fuzz,
        epss=epss,
    )

    # render refused (secret-lint rc=2 / completion-honesty rc=3) → sidecar
    # NOT written; propagate the exit code unchanged. No "Wrote" / integrity /
    # agent-status surfaces on this path (mirrors pre-refactor early raise).
    if result.rc != 0:
        raise typer.Exit(code=result.rc)

    # Post-flight integrity alert (does NOT fail the scan). run_scan
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

    # Surface a non-ok agent fallback on stderr (the report is still a clean
    # deterministic-only report; the scan still exits 0).
    if result.agent_status is not None and result.agent_status != "ok":
        typer.echo(
            f"agent: {result.agent_status} (deterministic-only report written)",
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
    """Show auto-detected stack(s) without running a full scan."""
    result = detect_stacks(Path(path).resolve())
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
        return
    if not result.stacks:
        typer.echo(
            "No stacks detected -- the universal collectors will still run on a scan."
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
    with_agent: bool = typer.Option(
        False,
        "--with-agent",
        help=(
            "Run the Claude agent on every repo in the sweep (AI narration per "
            "repo). Default: off — deterministic-only, which is fast, costs "
            "nothing, and avoids multiplying agent cost across many repos."
        ),
    ),
) -> None:
    """Sweep a directory of repos into a triage dashboard.

    Finds every immediate child of ``DIRECTORY`` that has a ``.git``, scans each
    one fresh and one at a time, and aggregates the per-repo JSON sidecars into
    a fleet snapshot. Writes a gitignored pair into repo-audit's own
    ``reports/`` directory:

        reports/fleet-{YYYY-MM-DD}.json            (machine-readable snapshot)
        reports/fleet-dashboard-{YYYY-MM-DD}.md    (the triage view)

    A repo whose scan fails becomes a dashboard row with its error reason and
    never aborts the sweep. Failed rows are pinned to the top; the rest are
    ranked worst-health-first. Both files pass the same secret-lint and
    completion-honesty checks as a single-repo report before they are written.

    Exit codes:
        0 — sweep completed (including when some repos failed — they are rows)
        2 — secret-lint refused the dashboard write
        3 — completion-honesty check refused the dashboard write
    """
    sweep_root = Path(directory).resolve()

    # Thin CLI: all sweep logic lives in run_fleet. Failures inside a repo are
    # rows (run_fleet isolates them); a sweep that produced zero repos is the
    # honest "nothing to scan" case, not an error.
    snapshot = run_fleet(sweep_root, with_agent=with_agent)

    if snapshot.total_repos == 0:
        typer.echo(f"No repos with .git found under {sweep_root}", err=True)
        raise typer.Exit(code=0)

    json_path, md_path = fleet_report_paths(sweep_root, snapshot.generated_date)

    # render_fleet_dashboard renders + lints BOTH buffers, then writes the pair
    # (md_path + its sibling .json). It derives the json path from md_path, so
    # the two must be the matching pair fleet_report_paths returns.
    rc = render_fleet_dashboard(snapshot, md_path)
    if rc != 0:
        # secret-lint (2) / completion-honesty (3) refused — nothing written.
        raise typer.Exit(code=rc)

    typer.echo(f"Wrote {json_path}")
    typer.echo(f"Wrote {md_path}")
    # One-line summary mirroring the dashboard's rollup header.
    cost = (
        "n/a"
        if snapshot.total_cost_usd is None
        else f"${snapshot.total_cost_usd:.2f}"
    )
    secs = (
        "n/a"
        if snapshot.sweep_seconds is None
        else f"{snapshot.sweep_seconds:.1f}s"
    )
    typer.echo(
        f"{snapshot.total_repos} repos scanned · "
        f"{snapshot.total_blockers} blockers, {snapshot.total_critical} critical "
        f"across fleet · {snapshot.failed_count} failed · "
        f"total cost {cost} · swept in {secs}"
    )


@app.command()
def issues(
    path: Path = typer.Argument(
        Path("."), help="Path to the scanned repo (carries the sidecar + origin)."
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help=(
            "Skip the interactive y/N confirmation and file immediately (for "
            "CI). Default: off — the command shows what it would file and "
            "asks first."
        ),
    ),
) -> None:
    """File confirmed findings as GitHub issues, after you approve them.

    Reads the most recent state-report sidecar, drafts one issue per confirmed
    critical/blocker finding plus one rollup issue per dimension, skips any that
    are already open, shows exactly what would be filed, and files nothing until
    you answer ``y`` (all or nothing). Filing uses ``gh issue create`` with a
    ``repo-audit`` label.

    Exit codes:
        0 — success (issues filed, nothing to file, or you declined)
        4 — gh unavailable, unauthenticated, or pointing at a different repo
        5 — no usable sidecar found (run `repo-audit scan` first)
    """
    repo_path = Path(path).resolve()

    def _print_dry_run(
        owner_repo: str,
        survivors: list,
        skipped_duplicate: list[tuple[str, str]],
    ) -> None:
        """Print the pre-gate dry-run to stdout (what a ``y`` would file).

        Lead with the resolved ``Owner/Repo`` target so the user sees
        EXACTLY which repo a ``y`` would write to before the y/N gate — the
        outward write goes to this repo and no other.
        """
        typer.echo(f"Filing to: {owner_repo}")
        typer.echo(f"Proposing {len(survivors)} issue(s) to file:")
        for draft in survivors:
            labels = ", ".join(draft.labels)
            typer.echo(f"  - [{draft.kind}] {draft.title}  ({labels})")
        for ref, existing_url in skipped_duplicate:
            typer.echo(f"  (skip duplicate) {ref} -> {existing_url}")

    result = run_issues(
        repo_path,
        assume_yes=yes,
        confirm=lambda: typer.confirm("File these issues?", default=False),
        on_propose=_print_dry_run,
    )

    # Diagnostic notes (staleness warning, no-sidecar reason, gh failures, abort)
    # go to stderr; the result report goes to stdout.
    for note in result.notes:
        typer.echo(note, err=True)

    # On a hard error (rc=4 wrong-repo/gh-unavailable, rc=5 no-sidecar) the
    # result envelope is empty, so the summary would print a misleading
    # "0 filed / 0 skipped / 0 blocked" to stdout — a script reading stdout would
    # see a "successful empty run" shape. Suppress the summary on a non-zero rc:
    # the real error is already on stderr.
    if result.rc != 0:
        raise typer.Exit(code=result.rc)

    typer.echo(result.summary())
