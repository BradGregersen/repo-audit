"""Plan 11-05 — the three Phase-11 cross-stack scan steps (test depth + Kotlin + Expo).

This module composes Plans 02-04 (detekt / coverage+kover / stryker+type-coverage
/ expo-doctor) into three never-raising cross-stack steps that ``scan_runner``
wires into ``run_scan`` exactly like ``run_sast`` / ``run_mobile`` (the Phase
7-10 precedent):

    * :func:`run_kotlin`    — wraps Plan-02 ``collect_detekt`` (KOT-01).
    * :func:`run_expo`      — wraps Plan-04 ``collect_expo_doctor`` (EXP-01).
    * :func:`run_test_depth` — composes the coverage (TST-01), mutation (TST-02),
      and type-coverage (TST-03) tiers, each degrading independently to
      unavailable/partial.

KEY CONTRACTS (the load-bearing decisions, mirrored from the plan):

    * D-11-03 — MUTATION IS OPT-IN. Stryker runs ONLY when ``mutation=True``; the
      default scan (and every fleet sweep) NEVER invokes it. ``run_scan`` defaults
      ``mutation=False`` and only the CLI ``--mutation`` flag flips it on.
    * D-11-05 — Stryker's hard cap is ``run_tool(timeout_seconds=1800)`` (a
      wall-clock cap with SIGTERM→5s→SIGKILL), NOT Stryker's own per-test
      millisecond flag (Pitfall 11 — that flag only bounds a single test run).
      On ``TIMED_OUT`` we read whatever ``reports/mutation/mutation.json`` exists
      and build an HONEST ``status="partial"`` mutation Finding.
    * D-11-02 — the in-place coverage/mutation runs are bracketed by the
      tracked-files-only git tripwire (``snapshot_git_status`` /
      ``diff_git_status``). A tracked-file change downgrades that tier to partial
      and names the offenders. Gitignored coverage / .stryker-tmp / reports
      artifacts do NOT appear in porcelain → not offenders by construction.
    * D-11-06 — the WEAK-test signal is emitted when line coverage outruns the
      mutation score by ``weak_threshold`` (default 25), phrased as a signal not a
      verdict, cross-linked to the coverage Finding.
    * SAFE-08 — every tier degrades to ``unavailable`` and the scan still
      COMPLETES when its tool/artifact is absent; nothing here ever raises.

The thresholds / timeouts / runner override are passed in by the caller
(``scan_runner`` reads the ``.repo-audit.yaml`` ``coverage_refresh`` /
``test_depth`` blocks). ``resolve_tool``, ``run_tool``, ``snapshot_git_status``,
``diff_git_status``, ``refresh``, ``parse_from_repo``, ``parse_kover_xml``,
``parse_type_coverage``, ``collect_detekt`` and ``collect_expo_doctor`` are
imported as MODULE-LEVEL names so tests can monkeypatch every seam without real
JVM / binary / git / filesystem I/O.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.expo.doctor import collect_expo_doctor
from repo_audit.adapters.kotlin.detekt import collect_detekt
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.adapters.typescript import refresh
from repo_audit.adapters.typescript.refresh import _NODE_STACKS
from repo_audit.adapters.typescript.parsers.kover_xml import parse_kover_xml
from repo_audit.adapters.typescript.parsers.lcov import parse_from_repo
from repo_audit.adapters.typescript.parsers.stryker_json import (
    build_mutation_finding,
    compute_mutation_score,
    weak_test_signal,
)
from repo_audit.adapters.typescript.parsers.type_coverage_json import (
    parse_type_coverage,
)
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.schema.finding import Finding

# --- envelope --------------------------------------------------------------

TestDepthStatus = Literal["ok", "partial", "unavailable", "timeout"]

# D-11-05 hard wall-clock cap for a Stryker mutation run (NOT the per-test ms flag).
_MUTATION_TIMEOUT_S: float = 1800.0
# A generous read-only type-coverage bound.
_TYPE_COVERAGE_TIMEOUT_S: float = 120.0
# Stryker writes its JSON report here under the repo root by default.
_MUTATION_REPORT_REL: str = "reports/mutation/mutation.json"
# Stacks whose coverage artifact is kover JaCoCo-XML (matches detect/rules.py kotlin-android tag).
_KOTLIN_STACK = "kotlin-android"


@dataclass
class TestDepthScanResult:
    """The never-raise envelope returned by the three steps (mirrors MobileScanResult).

    ``scan_runner`` reads ``findings`` into the merged finding set, ORs
    ``status != "ok"`` into the partial flag, and folds ``notes`` /
    ``ledger_notes`` into the scope ledger (SAFE-08 honest disclosure).
    """

    # Tell pytest NOT to collect this as a test class (name starts with "Test").
    __test__ = False

    findings: list[Finding] = field(default_factory=list)
    status: TestDepthStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


def _derive_status(statuses: list[str]) -> TestDepthStatus:
    """All-ok → ok / some-ok → partial / none → unavailable (mirror run_mobile)."""
    if statuses and all(s == "ok" for s in statuses):
        return "ok"
    if any(s == "ok" for s in statuses):
        return "partial"
    return "unavailable"


# --- run_kotlin (KOT-01) ---------------------------------------------------


def run_kotlin(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    attempt_typed: bool = True,
) -> TestDepthScanResult:
    """Never-raising detekt envelope (KOT-01). Absent JRE/jar → unavailable.

    Wraps Plan-02 ``collect_detekt``; maps its ``KotlinResult`` onto a
    :class:`TestDepthScanResult`. Any unexpected exception folds to
    ``status="unavailable"`` — NEVER raises (SAFE-08).
    """
    try:
        result = collect_detekt(
            repo_path, base_env, attempt_typed=attempt_typed
        )
    except Exception as exc:  # noqa: BLE001 — never crash the dimension
        return TestDepthScanResult(
            status="unavailable",
            notes=f"detekt failed unexpectedly: {type(exc).__name__}: {exc}",
            ledger_notes=[
                f"Kotlin/detekt unavailable: {type(exc).__name__}: {exc}"
            ],
        )

    ledger_notes: list[str] = []
    if result.status != "ok":
        ledger_notes.append(f"detekt {result.status}: {result.notes}")
    return TestDepthScanResult(
        findings=list(result.findings),
        status=result.status,  # type: ignore[arg-type]
        notes=result.notes,
        ledger_notes=ledger_notes,
    )


# --- run_expo (EXP-01) -----------------------------------------------------


def run_expo(
    repo_path: Path,
    *,
    base_env: dict[str, str],
) -> TestDepthScanResult:
    """Never-raising expo-doctor envelope (EXP-01). Absent tool → unavailable.

    Wraps Plan-04 ``collect_expo_doctor`` (which returns a ``list[Finding]``); a
    lone unavailable/timeout Finding derives the unavailable/timeout status.
    NEVER raises.
    """
    try:
        findings = collect_expo_doctor(repo_path, base_env)
    except Exception as exc:  # noqa: BLE001 — never crash the dimension
        return TestDepthScanResult(
            status="unavailable",
            notes=f"expo-doctor failed unexpectedly: {type(exc).__name__}: {exc}",
            ledger_notes=[
                f"Expo/expo-doctor unavailable: {type(exc).__name__}: {exc}"
            ],
        )

    status: TestDepthStatus = "ok"
    ledger_notes: list[str] = []
    if len(findings) == 1 and findings[0].evidence_type == "unavailable":
        reason = findings[0].evidence.parsed_value.get("reason", "")
        status = "timeout" if reason == "expo_doctor_timeout" else "unavailable"
        ledger_notes.append(
            f"expo-doctor {status}: {findings[0].evidence.output_snippet}"
        )
    return TestDepthScanResult(
        findings=list(findings),
        status=status,
        notes=f"expo-doctor: {len(findings)} finding(s)",
        ledger_notes=ledger_notes,
    )


# --- run_test_depth tiers --------------------------------------------------


def _run_coverage_tier(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    stack: str,
    override: Optional[dict],
) -> tuple[list[Finding], str, list[str]]:
    """TST-01 coverage tier: resolve the runner, run it in-place (tripwire-bracketed),
    then parse the produced artifact (kover for kotlin, lcov otherwise).

    Returns ``(findings, status, ledger_notes)``. NEVER raises.
    """
    ledger_notes: list[str] = []

    cmd = refresh.resolve_runner_command(repo_path, stack=stack, override=override)
    if cmd is None:
        return (
            [],
            "unavailable",
            ["coverage runner unavailable (no confident command)"],
        )

    # D-11-02 tripwire: snapshot tracked git status BEFORE the in-place run.
    pre = snapshot_git_status(repo_path)
    refresh_cfg = {"command": cmd}
    if override and override.get("timeout_ms"):
        refresh_cfg["timeout_ms"] = override["timeout_ms"]
    rr = refresh.refresh_coverage(repo_path, refresh_cfg, base_env)
    offenders = diff_git_status(pre, snapshot_git_status(repo_path))
    rr_status = getattr(rr, "status", "")

    # W3 (reproducibility / no-invent-numbers): only present the parsed concrete
    # coverage percentage when the refresh ACTUALLY succeeded this run. A failed /
    # timed-out refresh must NOT surface a pre-existing on-disk artifact's numbers
    # as this run's result — degrade honestly with no concrete-percentage Finding.
    if rr_status != "ok":
        ledger_notes.append(
            f"coverage refresh {rr_status or '?'}; not emitting stale on-disk "
            "coverage numbers for this run"
        )
        # "partial" when the runner produced output but didn't succeed; "unavailable"
        # when it never ran at all (no output/sentinel).
        status = "partial" if rr_status else "unavailable"
        # D-11-02 still applies: a tracked-file change names the offenders.
        if offenders:
            status = "partial"
            ledger_notes.append(
                "coverage runner modified tracked files (downgraded to partial): "
                + "; ".join(offenders)
            )
        return ([], status, ledger_notes)

    status = "ok"

    # Refresh succeeded — parse the produced artifact for the resolved stack.
    if stack == _KOTLIN_STACK:
        findings = parse_kover_xml(repo_path)
    else:
        findings = parse_from_repo(repo_path)

    # D-11-02: a tracked-file change downgrades the tier to partial + names it.
    if offenders:
        status = "partial"
        ledger_notes.append(
            "coverage runner modified tracked files (downgraded to partial): "
            + "; ".join(offenders)
        )

    return (findings, status, ledger_notes)


def _read_mutation_report(repo_path: Path) -> Optional[dict]:
    """Read ``reports/mutation/mutation.json`` if present; None on any failure."""
    report_path = Path(repo_path) / _MUTATION_REPORT_REL
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_mutation_tier(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    mutation_timeout_s: float,
) -> tuple[list[Finding], str, list[str], Optional[dict]]:
    """TST-02 mutation tier (D-11-03 opt-in only — the caller gates ``mutation``).

    Bracketed by the D-11-02 tripwire. Resolves ``stryker`` and runs it through
    ``run_tool`` with the D-11-05 hard cap. On TIMED_OUT a partial mutation.json
    still yields a partial Finding. Returns
    ``(findings, status, ledger_notes, report)`` so the caller can wire the WEAK
    signal. NEVER raises.
    """
    ledger_notes: list[str] = []

    stryker = resolve_tool("stryker", repo_path)
    if stryker is None:
        return ([], "unavailable", ["mutation: stryker not resolved"], None)

    pre = snapshot_git_status(repo_path)
    inv = run_tool(
        [str(stryker), "run", "--reporters", "json"],
        env=base_env,
        cwd=repo_path,
        # D-11-05: hard wall-clock cap via run_tool, NOT Stryker's per-test
        # millisecond flag (Pitfall 11 — that only bounds a single test run).
        timeout_seconds=mutation_timeout_s,
    )
    offenders = diff_git_status(pre, snapshot_git_status(repo_path))

    findings: list[Finding] = []
    report: Optional[dict] = None
    status = "ok"

    if inv.returncode == TIMED_OUT:
        # D-11-05: read whatever partial report exists → honest partial Finding.
        report = _read_mutation_report(repo_path)
        if report is not None:
            findings.append(build_mutation_finding(report, status="partial"))
            status = "partial"
        else:
            ledger_notes.append("mutation timed out, no partial report")
            status = "unavailable"
    elif inv.returncode == EXEC_FAILED:
        ledger_notes.append(f"mutation: stryker could not be executed: {inv.stderr}")
        status = "unavailable"
    elif inv.returncode == 0:
        report = _read_mutation_report(repo_path)
        if report is not None:
            compute_mutation_score(report)  # validates shape; no exceptions
            findings.append(build_mutation_finding(report, status="ok"))
        else:
            ledger_notes.append("mutation ran but produced no parseable report")
            status = "unavailable"
    else:
        # Non-zero, non-sentinel exit (e.g. Stryker rc=1 error exit). A stale
        # reports/mutation/mutation.json from a PRIOR run must NOT be trusted as
        # this run's result — degrade honestly, never emit a confident score
        # from a run that errored (no-invent-numbers / reproducibility constraint).
        # `report` stays None so the WEAK-signal threading in run_test_depth also
        # cannot fire off a failed run.
        ledger_notes.append(
            f"mutation: stryker exited non-zero ({inv.returncode}); "
            "not trusting any on-disk report from this run"
        )
        status = "unavailable"

    if offenders:
        status = "partial"
        ledger_notes.append(
            "mutation run modified tracked files (downgraded to partial): "
            + "; ".join(offenders)
        )

    return (findings, status, ledger_notes, report)


def _run_type_coverage_tier(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    stack: str,
) -> tuple[list[Finding], str, list[str]]:
    """TST-03 type-coverage tier (READ-ONLY — no tripwire needed).

    Resolves ``type-coverage``; a LOCAL binary runs on any stack. When no local
    binary exists, the ``npx type-coverage`` network fallback is gated to node
    stacks ONLY (W2 — T-11-06-01): on a non-node repo with no local binary the
    tier degrades to ``unavailable`` rather than fetching + executing an arbitrary
    npm package from the network. NEVER raises.
    """
    ledger_notes: list[str] = []

    tc = resolve_tool("type-coverage", repo_path)
    if tc is not None:
        argv = [str(tc), "--json-output"]
    elif stack in _NODE_STACKS:
        argv = ["npx", "type-coverage", "--json-output"]
    else:
        # W2: no local binary AND non-node stack — never trigger an npx network
        # download/execution on a repo where type-coverage doesn't belong.
        return (
            [],
            "unavailable",
            [
                "type-coverage: no local binary and stack is not node — "
                "skipping npx network fallback"
            ],
        )
    inv = run_tool(
        argv, env=base_env, cwd=repo_path, timeout_seconds=_TYPE_COVERAGE_TIMEOUT_S
    )

    if inv.returncode == TIMED_OUT:
        return ([], "unavailable", ["type-coverage timed out"])
    if inv.returncode == EXEC_FAILED:
        return ([], "unavailable", [f"type-coverage not executed: {inv.stderr}"])

    # RESEARCH A2/Open Q2: read stdout first, fall back to a known output file.
    data: Optional[dict] = None
    try:
        data = json.loads(inv.stdout) if inv.stdout else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        for rel in ("type-coverage.json", "coverage/type-coverage.json"):
            candidate = Path(repo_path) / rel
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                break
            except (OSError, ValueError):
                data = None
    if not isinstance(data, dict):
        return ([], "unavailable", ["type-coverage produced no parseable JSON"])

    findings = parse_type_coverage(data)
    return (findings, "ok", ledger_notes)


def run_test_depth(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    refresh_coverage: bool = False,
    mutation: bool = False,
    stack: str = "typescript-node",
    override: Optional[dict] = None,
    weak_threshold: float = 25.0,
    mutation_timeout_s: float = _MUTATION_TIMEOUT_S,
) -> TestDepthScanResult:
    """Compose the coverage / mutation / type-coverage tiers (TST-01/02/03).

    Each tier is independently never-raising; the overall status is derived from
    the per-tier statuses (all-ok→ok / some-ok→partial / none→unavailable).
    Mutation runs ONLY when ``mutation=True`` (D-11-03 opt-in); the default scan
    never invokes Stryker. NEVER raises across the function (SAFE-08).

    Args:
        repo_path: target repository root.
        base_env: child env (a ``build_scan_env`` tempdir env) for every tier.
        refresh_coverage: when True, run the coverage tier (in-place, tripwired).
        mutation: D-11-03 opt-in — run the Stryker mutation tier (NEVER default).
        stack: the primary detected stack (drives the coverage runner + artifact).
        override: the ``.repo-audit.yaml`` coverage_refresh block, if any.
        weak_threshold: D-11-06 gap threshold for the WEAK-test signal.
        mutation_timeout_s: D-11-05 Stryker hard wall-clock cap (default 1800s).

    Returns:
        A :class:`TestDepthScanResult`; never raises.
    """
    findings: list[Finding] = []
    ledger_notes: list[str] = []
    statuses: list[str] = []
    coverage_line_pct: Optional[float] = None

    # --- COVERAGE tier (TST-01) -------------------------------------------
    if refresh_coverage:
        try:
            cov_findings, cov_status, cov_notes = _run_coverage_tier(
                repo_path, base_env=base_env, stack=stack, override=override
            )
        except Exception as exc:  # noqa: BLE001 — tier never crashes the step
            cov_findings, cov_status, cov_notes = (
                [],
                "unavailable",
                [f"coverage tier failed: {type(exc).__name__}: {exc}"],
            )
        findings.extend(cov_findings)
        statuses.append(cov_status)
        ledger_notes.extend(cov_notes)
        # Capture the coverage line_pct for the WEAK signal cross-link.
        for f in cov_findings:
            if f.rule_id == "coverage_summary":
                pv = f.evidence.parsed_value or {}
                lp = pv.get("line_pct")
                if isinstance(lp, (int, float)):
                    coverage_line_pct = float(lp)
                break

    # --- MUTATION tier (TST-02, D-11-03 opt-in ONLY) ----------------------
    if mutation:
        try:
            (
                mut_findings,
                mut_status,
                mut_notes,
                mut_report,
            ) = _run_mutation_tier(
                repo_path,
                base_env=base_env,
                mutation_timeout_s=mutation_timeout_s,
            )
        except Exception as exc:  # noqa: BLE001 — tier never crashes the step
            mut_findings, mut_status, mut_notes, mut_report = (
                [],
                "unavailable",
                [f"mutation tier failed: {type(exc).__name__}: {exc}"],
                None,
            )
        findings.extend(mut_findings)
        statuses.append(mut_status)
        ledger_notes.extend(mut_notes)

        # D-11-06 WEAK signal: only when BOTH a coverage line_pct and a mutation
        # score were produced this run.
        if mut_report is not None and coverage_line_pct is not None:
            try:
                score = compute_mutation_score(mut_report)
                weak = weak_test_signal(
                    coverage_line_pct,
                    score,
                    {"rule_id": "coverage_summary"},
                    threshold=weak_threshold,
                )
                if weak is not None:
                    findings.append(weak)
            except Exception:  # noqa: BLE001 — never crash on signal computation
                pass

    # --- TYPE-COVERAGE tier (TST-03, READ-ONLY) ---------------------------
    try:
        tc_findings, tc_status, tc_notes = _run_type_coverage_tier(
            repo_path, base_env=base_env, stack=stack
        )
    except Exception as exc:  # noqa: BLE001 — tier never crashes the step
        tc_findings, tc_status, tc_notes = (
            [],
            "unavailable",
            [f"type-coverage tier failed: {type(exc).__name__}: {exc}"],
        )
    findings.extend(tc_findings)
    statuses.append(tc_status)
    ledger_notes.extend(tc_notes)

    status = _derive_status(statuses)
    notes_parts = [f"test-depth: {len(findings)} finding(s)"]
    return TestDepthScanResult(
        findings=findings,
        status=status,
        notes="; ".join(notes_parts),
        ledger_notes=ledger_notes,
    )


__all__ = [
    "TestDepthScanResult",
    "TestDepthStatus",
    "run_test_depth",
    "run_kotlin",
    "run_expo",
]
