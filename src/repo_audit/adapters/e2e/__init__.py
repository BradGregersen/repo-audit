"""E2E lane package (E2E-01, Plan 16-02).

The deepest precondition lane: E2E needs a built app + a booted device/browser.
Its defining behavior is the TRI-STATE (D-16-02):

  * no harness            → ``status="not_applicable"`` ("no E2E configured"),
  * harness present, unrun → ``status="unavailable"`` naming WHY (not opted in /
    infra absent) so a configured-but-unrun harness is NEVER conflated with
    "no harness" (Pitfall 1),
  * ran                    → ``status="ok"`` / ``"partial"`` (pass/fail parsed),
                             ``"timeout"`` if the run timed out.

This is ``run_test_depth`` re-shaped. ``run_e2e``:

  * NEVER auto-authors a spec and NEVER instruments the repo (D-25 /
    T-16-02-04) — it runs only what the repo already declares, brackets any
    in-place run with the git tripwire, and reads coverage best-effort only.
  * NEVER raises and NEVER hangs — every failure mode folds into a status; the
    ``run_tool`` SIGTERM→5s→SIGKILL cap backs the no-hang guarantee.

``resolve_tool``, ``run_tool``, ``EXEC_FAILED``, ``TIMED_OUT``,
``snapshot_git_status`` and ``diff_git_status`` are imported as MODULE-LEVEL
names so tests can monkeypatch every seam without real binary / git / fs I/O.
``E2eScanResult`` is copied VERBATIM from ``test_depth.TestDepthScanResult``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.e2e import parsers, runners
from repo_audit.adapters.e2e.config import E2eConfig, read_e2e_config
from repo_audit.adapters.e2e.detect import detected_harnesses, harness_state
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.schema.finding import Finding

# Tri-state (D-16-02): not_applicable = no harness; unavailable = harness present
# but not run (named precondition); ok/partial = ran; timeout = run timed out.
E2eStatus = Literal["ok", "partial", "unavailable", "timeout", "not_applicable"]

# E2E tools are PROJECT test tools → the default resolve ladder (project-local
# preferred), NOT trusted_only.
_PLAYWRIGHT_TOOL = "playwright"


@dataclass
class E2eScanResult:
    """The never-raise envelope returned by the E2E lane (mirrors TestDepthScanResult).

    ``scan_runner`` reads ``findings`` into the merged finding set, ORs
    ``status != "ok"`` into the partial flag, and folds ``notes`` /
    ``ledger_notes`` into the scope ledger (SAFE-08 honest disclosure).
    """

    # Tell pytest NOT to collect this as a test class.
    __test__ = False

    findings: list[Finding] = field(default_factory=list)
    status: E2eStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)
    # Best-effort coverage percentage (D-16-03). None = unavailable / not invented.
    coverage_pct: float | None = None


def detect(repo_path: Path) -> E2eScanResult:
    """Tri-state detection entry point (D-16-02), WITHOUT running the harness.

    Resolves the *none vs present* legs into a result-bearing envelope:

      * no harness → ``status="not_applicable"``, note "no E2E configured".
      * harness present (but this entry never runs it) → ``status="unavailable"``
        with a note naming the detected harness + "detected, not run" so a
        configured-but-unrun harness is never conflated with "no E2E configured"
        (Pitfall 1).

    READ-ONLY, NEVER raises. The full opt-in run path is :func:`run_e2e`.
    """
    harnesses = detected_harnesses(Path(repo_path))
    if not harnesses:
        return E2eScanResult(
            status="not_applicable",
            notes="no E2E configured (no Detox/Maestro/Playwright harness detected)",
            ledger_notes=["E2E not applicable: no E2E harness configured"],
        )
    names = ", ".join(harnesses)
    return E2eScanResult(
        status="unavailable",
        notes=(
            f"E2E harness detected ({names}) but not run — "
            "not opted in / infra unavailable"
        ),
        ledger_notes=[f"E2E harness present ({names}) — detected, not run"],
    )


def coverage(repo_path: Path, td: Optional[Path] = None) -> E2eScanResult:
    """Best-effort E2E coverage entry point (D-16-03), WITHOUT running the harness.

    Reads an already-emitted V8/coverage-summary artifact if present; absent → a
    ``status="unavailable"`` envelope with ``coverage_pct=None`` (NEVER
    instruments the repo, NEVER fabricates a number — T-16-02-04). NEVER raises.
    """
    pct = parsers.read_v8_coverage(Path(repo_path), td)
    if pct is None:
        return E2eScanResult(
            status="unavailable",
            notes=(
                "E2E coverage unavailable: no already-emitted coverage artifact "
                "(repo NOT instrumented — D-16-03)"
            ),
            coverage_pct=None,
        )
    return E2eScanResult(
        status="ok",
        notes=f"E2E line coverage: {pct:.1f}%",
        coverage_pct=pct,
    )


def _present_not_run(harnesses: list[str], reason: str) -> E2eScanResult:
    """Build the distinct 'detected-not-run' unavailable result (D-16-02)."""
    names = ", ".join(harnesses)
    return E2eScanResult(
        status="unavailable",
        notes=f"E2E harness detected ({names}) but not run — {reason}",
        ledger_notes=[f"E2E harness present ({names}) — detected, not run: {reason}"],
    )


def run_e2e(
    repo_path: Path,
    *,
    base_env: Optional[dict[str, str]] = None,
    opt_in: bool = False,
    infra_present: bool = False,
    config: Optional[E2eConfig] = None,
) -> E2eScanResult:
    """Tri-state E2E run (E2E-01 / D-16-02). NEVER auto-authors, instruments, or raises.

    Flow:
      * ``harness_state`` ``"none"`` → ``not_applicable`` ("no E2E configured").
      * ``"present"`` AND (not ``opt_in`` OR not ``infra_present`` OR Playwright
        unresolved) → ``unavailable`` naming the harness + the missing
        precondition (D-16-02). The throwaway-copy build is NOT attempted here
        (Pitfall 2 — degrade to detected-not-run rather than dirty the tree).
      * otherwise → snapshot git → ``run_tool`` (timeout from config) → diff →
        parse Playwright JSON → derive status → best-effort coverage. Tracked-file
        offenders downgrade to ``partial`` and are named in ``ledger_notes``.

    Args:
        repo_path: target repository root.
        base_env: child env for the harness run; a cache-redirected scan env is
            built when omitted (so the entry point is callable with just a repo).
        opt_in: the future ``--e2e`` flag — default False NEVER runs (T-16-02-01).
        infra_present: whether the precondition (built app + booted device/
            browser) is satisfied. Default False degrades to detected-not-run.
        config: resolved :class:`E2eConfig`; read from the repo when omitted.

    Returns:
        An :class:`E2eScanResult`; never raises, never hangs.
    """
    repo = Path(repo_path)
    cfg = config if config is not None else read_e2e_config(repo)

    harnesses = detected_harnesses(repo)
    if not harnesses:
        return E2eScanResult(
            status="not_applicable",
            notes="no E2E configured (no Detox/Maestro/Playwright harness detected)",
            ledger_notes=["E2E not applicable: no E2E harness configured"],
        )

    if not opt_in:
        return _present_not_run(harnesses, "not opted in (--e2e off)")
    if not infra_present:
        return _present_not_run(
            harnesses, "infra unavailable (no built app / booted device or browser)"
        )

    # Opt-in + infra present: attempt the in-place run. Only the Playwright
    # path is wired for the JSON result here; other harnesses degrade honestly.
    if "playwright" not in harnesses:
        return _present_not_run(
            harnesses, "no runnable Playwright harness wired for in-place run"
        )

    binary = resolve_tool(_PLAYWRIGHT_TOOL, repo)
    if binary is None:
        return _present_not_run(harnesses, "playwright binary not resolved")

    # Build a cache-redirected env when the caller didn't supply one.
    if base_env is not None:
        return _run_playwright(repo, base_env, cfg)
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        return _run_playwright(repo, env, cfg, td=tempdir)


def _run_playwright(
    repo: Path,
    base_env: dict[str, str],
    cfg: E2eConfig,
    *,
    td: Optional[Path] = None,
) -> E2eScanResult:
    """Run the resolved Playwright harness in-place, tripwire-bracketed. NEVER raises."""
    ledger_notes: list[str] = []
    binary = resolve_tool(_PLAYWRIGHT_TOOL, repo)
    if binary is None:  # pragma: no cover — caller already checked
        return _present_not_run(["playwright"], "playwright binary not resolved")

    # D-16-02 / T-16-02-01 tripwire: snapshot tracked git status BEFORE the run.
    pre = snapshot_git_status(repo)
    inv = run_tool(
        runners.playwright_argv(binary, repo),
        env=base_env,
        cwd=repo,
        timeout_seconds=float(cfg.timeout_seconds),
    )
    offenders = diff_git_status(pre, snapshot_git_status(repo))

    if inv.returncode == EXEC_FAILED:
        return _present_not_run(["playwright"], f"playwright exec failed: {inv.stderr}")

    findings: list[Finding] = []
    status: E2eStatus = "ok"

    timed_out = inv.returncode == TIMED_OUT
    # Playwright exits non-zero when tests fail, so we parse the JSON regardless
    # of returncode (the report, not the exit code, is the source of truth).
    passed, failed, total = parsers.parse_playwright_json(inv.stdout or "")
    if total == 0 and not timed_out:
        # No parseable result and the run did not time out → nothing usable.
        return _present_not_run(["playwright"], "playwright produced no parseable report")

    findings.append(
        parsers.build_result_finding(passed, failed, total, source_tool="playwright")
    )
    if timed_out:
        status = "partial"
        ledger_notes.append(
            f"playwright timed out after {cfg.timeout_seconds}s; "
            "reporting partial result"
        )

    # Best-effort coverage (D-16-03): read an already-emitted artifact only.
    coverage_pct: float | None = None
    if cfg.coverage:
        coverage_pct = parsers.read_v8_coverage(repo, td)
        findings.append(
            parsers.build_coverage_finding(coverage_pct, source_tool="playwright")
        )

    # T-16-02-01: a tracked-file change downgrades to partial + names offenders.
    if offenders:
        status = "partial"
        ledger_notes.append(
            "E2E run modified tracked files (downgraded to partial): "
            + "; ".join(offenders)
        )

    return E2eScanResult(
        findings=findings,
        status=status,
        notes=f"playwright: {passed} passed, {failed} failed, {total} total",
        ledger_notes=ledger_notes,
        coverage_pct=coverage_pct,
    )


__all__ = [
    "E2eScanResult",
    "E2eStatus",
    "run_e2e",
    "detect",
    "coverage",
    "harness_state",
    "detected_harnesses",
    "E2eConfig",
    "read_e2e_config",
]
