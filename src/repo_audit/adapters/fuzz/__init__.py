"""Fuzz lane (FUZZ-01) — the ``run_fuzz`` SPLIT-TRIGGER envelope (Plan 16-03).

This is ``test_depth.py::_run_mutation_tier`` re-shaped with a 60-120s budget
instead of 1800s. The SPLIT TRIGGER (D-16-04):

  * **fast-check** (bounded property tests) is DETECT-ONLY this phase. It has no
    standalone CLI — it runs inside the project's normal Jest/Vitest test run, so
    the lane only SURFACES its presence as a signal and NEVER invokes it
    (Pitfall 4 / Assumption A1).
  * **native libFuzzer engines** (atheris / jazzer) are OPT-IN (the future
    ``--fuzz`` flag) and run under a SHORT WALL-CLOCK BUDGET. The authoritative
    bound is ``run_tool(timeout_seconds=config.budget_seconds)`` (Pitfall 3 — NOT
    the engine's ``-max_total_time``; a native fuzzer runs until killed). On
    ``TIMED_OUT`` we report whatever counterexamples surfaced as
    ``status='partial'`` (fact + crash-file + location ONLY — NEVER raw bytes,
    T-16-03-01).

  * **un-fuzzed high-value surfaces** → candidate INFORMATIONAL signals (D-16-06,
    via ``detect.candidate_surfaces``); never a generated target.

The native run is bracketed by the tracked-files-only git tripwire
(``snapshot_git_status`` / ``diff_git_status``): a tracked-file change downgrades
to ``partial`` and names the offenders (T-16-03-03 backstop on opt-in execution).

Every seam (``resolve_tool``, ``run_tool``, ``EXEC_FAILED``, ``TIMED_OUT``,
``snapshot_git_status``, ``diff_git_status``, ``fastcheck_present``,
``native_targets``, ``candidate_surfaces``, ``parse_libfuzzer_crashes``) is a
MODULE-LEVEL name so tests can monkeypatch every boundary (the
``test_sast_semgrep.py`` precedent). NEVER raises (SAFE-08 / D-25).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.fuzz.config import FuzzConfig, read_fuzz_config
from repo_audit.adapters.fuzz.detect import (
    FuzzEngine,
    FuzzTarget,
    candidate_surfaces,
    fastcheck_present,
    native_targets,
)
from repo_audit.adapters.fuzz.libfuzzer import (
    CrashSummary,
    build_crash_findings,
    parse_libfuzzer_crashes,
)
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.schema.finding import Evidence, Finding

# --- envelope (copied from TestDepthScanResult, renamed, __test__=False) ----

FuzzStatus = Literal["ok", "partial", "unavailable", "timeout", "not_applicable"]

# Engine binary names per detected target engine (resolved per-target).
_ENGINE_BINARY: dict[str, str] = {"atheris": "python", "jazzer": "jazzer"}


@dataclass
class FuzzScanResult:
    """The never-raise envelope returned by :func:`run_fuzz` (mirrors the Phase-11
    ``TestDepthScanResult``). ``scan_runner`` reads ``findings`` into the merged
    set, ORs ``status != "ok"`` into the partial flag, and folds
    ``notes`` / ``ledger_notes`` into the scope ledger (SAFE-08).
    """

    __test__ = False

    findings: list[Finding] = field(default_factory=list)
    status: FuzzStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


@dataclass
class FuzzDetectResult:
    """READ-ONLY detection summary (the ``detect`` entry the lane exposes).

    Pure detection — runs nothing. ``status='ok'`` when any fuzz-related signal is
    present, else ``not_applicable``.
    """

    __test__ = False

    fastcheck: bool = False
    targets: list[FuzzTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "not_applicable"


def _derive_status(statuses: list[str]) -> FuzzStatus:
    """Derive the overall native-run status from per-target statuses.

    All-ok → ok. Any productive outcome (a clean ``ok`` AND a degraded
    ``partial`` mix, or any ``partial``) → partial. Only when EVERY target
    failed to run (all ``unavailable`` / ``timeout``) → unavailable. A surfaced
    counterexample under the budget arrives as a per-target ``partial`` and must
    NOT collapse to ``unavailable`` (that would hide the honest finding).
    """
    if not statuses:
        return "unavailable"
    if all(s == "ok" for s in statuses):
        return "ok"
    if any(s in ("ok", "partial") for s in statuses):
        return "partial"
    return "unavailable"


def detect(repo_path: Path) -> FuzzDetectResult:
    """READ-ONLY fuzz detection (Pitfall 4 — never invokes fast-check).

    Gathers the fast-check presence signal, native targets, and candidate-surface
    signals without running anything. ``status='ok'`` when any signal is present,
    else ``not_applicable``. Never raises.
    """
    repo = Path(repo_path)
    fc = fastcheck_present(repo)
    targets = native_targets(repo)
    fuzzed = {t.path for t in targets}
    cand = candidate_surfaces(repo, fuzzed)
    has_signal = fc or bool(targets) or bool(cand)
    return FuzzDetectResult(
        fastcheck=fc,
        targets=targets,
        findings=cand,
        status="ok" if has_signal else "not_applicable",
    )


def _fastcheck_signal_finding(repo_rel: str = "package.json") -> Finding:
    """Build the fast-check PRESENCE signal Finding (detect-only, never a run)."""
    return Finding(
        dimension="test_integrity",
        severity="info",
        evidence_type="static",
        confidence="candidate",
        source_tool="fuzz",
        source_collector="fuzz_fastcheck",
        rule_id="fastcheck_present",
        file=repo_rel,
        recommendation=(
            "Property-based testing (fast-check) is present — it runs inside the "
            "project's normal test suite. A positive signal; the lane detects it "
            "but never invokes fast-check standalone (it has no separate CLI)."
        ),
        evidence=Evidence(
            tool="fuzz-detect",
            output_snippet="fast-check declared in package.json (detect-only signal)",
            parsed_value={"signal": "fastcheck_present"},
        ),
    )


def _run_native_target(
    target: FuzzTarget,
    repo_path: Path,
    *,
    base_env: dict[str, str],
    budget_seconds: float,
) -> tuple[list[Finding], str, list[str]]:
    """Run ONE native target under the wall-clock budget; honest partial on timeout.

    Mirrors ``test_depth.py::_run_mutation_tier``: resolve → snapshot → run_tool
    (budget) → diff → on TIMED_OUT/exit read stderr → parse_libfuzzer_crashes →
    partial. EXEC_FAILED / resolve None → unavailable for that target. A
    tracked-file change downgrades to partial + names the offenders. NEVER raises.

    Returns ``(findings, status, ledger_notes)``.
    """
    ledger_notes: list[str] = []
    binary = _ENGINE_BINARY.get(target.engine, target.engine)
    # Native fuzzers execute the TARGET's code — they are the target's dev deps;
    # resolve through the default (project) ladder, NOT trusted_only.
    resolved = resolve_tool(binary, repo_path)
    if resolved is None:
        return (
            [],
            "unavailable",
            [f"fuzz: {target.engine} runner '{binary}' not resolved for {target.path}"],
        )

    # T-16-03-03 backstop: snapshot tracked git status BEFORE the in-place run.
    pre = snapshot_git_status(repo_path)
    inv = run_tool(
        [str(resolved), target.path],
        env=base_env,
        cwd=repo_path,
        # Pitfall 3 / D-16-05: the AUTHORITATIVE bound is run_tool's wall-clock
        # cap, NOT the engine's own -max_total_time (a native fuzzer runs until
        # killed). SIGTERM→5s→SIGKILL is handled inside run_tool.
        timeout_seconds=budget_seconds,
    )
    offenders = diff_git_status(pre, snapshot_git_status(repo_path))

    findings: list[Finding] = []
    status = "ok"

    if inv.returncode == EXEC_FAILED:
        ledger_notes.append(
            f"fuzz: {target.engine} could not be executed for {target.path}: "
            f"{inv.stderr}"
        )
        status = "unavailable"
    else:
        # On TIMED_OUT (D-16-04/05) OR a crashing non-zero exit, libFuzzer has
        # printed the crash report to stderr. Parse FACT + LOCATION only — never
        # the crash-<sha1> bytes (T-16-03-01).
        summaries: list[CrashSummary] = parse_libfuzzer_crashes(inv.stderr, repo_path)
        if summaries:
            findings.extend(build_crash_findings(summaries))
            # A surfaced counterexample under a budgeted run is an honest PARTIAL:
            # the fuzzer was killed by our cap, reporting what it found so far.
            status = "partial"
            ledger_notes.append(
                f"fuzz: {target.engine} on {target.path} surfaced "
                f"{len(summaries)} counterexample(s) "
                f"({'timed out' if inv.returncode == TIMED_OUT else 'crashing exit'})"
            )
        elif inv.returncode == TIMED_OUT:
            # Timed out with no parseable crash → partial coverage, no counterexample.
            status = "partial"
            ledger_notes.append(
                f"fuzz: {target.engine} on {target.path} timed out under the "
                f"{budget_seconds:.0f}s budget with no counterexample surfaced"
            )
        # else: clean exit (returncode 0, no crash) → status stays "ok".

    # T-16-03-03: a tracked-file change downgrades to partial + names offenders.
    if offenders:
        status = "partial"
        ledger_notes.append(
            "fuzz: native run modified tracked files (downgraded to partial): "
            + "; ".join(offenders)
        )

    return (findings, status, ledger_notes)


def run_fuzz(
    repo_path: Path,
    *,
    base_env: Optional[dict[str, str]] = None,
    opt_in: bool = False,
    config: Optional[FuzzConfig] = None,
) -> FuzzScanResult:
    """The SPLIT-TRIGGER fuzz envelope (fast-check detect-only / native opt-in).

    Args:
        repo_path: target repository root.
        base_env: child env for native runs. Defaults to a copy of ``os.environ``
            so a single-positional call (the Wave-0 contract) still works.
        opt_in: the future ``--fuzz`` gate. When False, native engines are NEVER
            invoked (only detection/candidate signals are surfaced).
        config: a :class:`FuzzConfig`; when None it is read from the repo's
            ``.repo-audit.yaml`` at call time (defaults on absence).

    Flow (D-16-04):
        1. ALWAYS collect (read-only) the fast-check presence signal + the
           candidate-surface signals.
        2. No fast-check AND no native target → ``not_applicable``.
        3. fast-check present, no native target → carry the fast-check + candidate
           signals; native engines NOT invoked.
        4. native target present but ``opt_in`` False → ``unavailable`` with a
           "present but not opted in" note (Pitfall 1 — never collapse
           present-not-run into none).
        5. ``opt_in`` True + native target → run each under the wall-clock budget;
           TIMED_OUT/crash → ``partial`` with counterexamples (fact+location only).

    NEVER raises (SAFE-08 / D-25).
    """
    repo = Path(repo_path)
    env = dict(base_env) if base_env is not None else dict(os.environ)
    cfg = config if config is not None else read_fuzz_config(repo)

    findings: list[Finding] = []
    ledger_notes: list[str] = []

    # --- (1) ALWAYS-on read-only signals ----------------------------------
    fc_present = False
    try:
        fc_present = fastcheck_present(repo)
    except Exception as exc:  # noqa: BLE001 — detection never crashes the lane
        ledger_notes.append(f"fuzz: fast-check detection failed: {type(exc).__name__}")
    if fc_present:
        findings.append(_fastcheck_signal_finding())
        ledger_notes.append("fuzz: fast-check present (detect-only signal, Pitfall 4)")

    try:
        targets = native_targets(repo)
    except Exception as exc:  # noqa: BLE001
        targets = []
        ledger_notes.append(f"fuzz: native-target detection failed: {type(exc).__name__}")

    try:
        cand = candidate_surfaces(repo, {t.path for t in targets})
    except Exception as exc:  # noqa: BLE001
        cand = []
        ledger_notes.append(f"fuzz: candidate-surface scan failed: {type(exc).__name__}")
    findings.extend(cand)

    # --- (2) nothing fuzz-related → not_applicable ------------------------
    if not fc_present and not targets:
        notes = "fuzz: no fuzz/property suites configured"
        if cand:
            # Candidate surfaces are informational; still not_applicable as a run.
            ledger_notes.append(
                f"fuzz: {len(cand)} un-fuzzed candidate surface(s) flagged "
                "(no suites configured)"
            )
        return FuzzScanResult(
            findings=findings,
            status="not_applicable",
            notes=notes,
            ledger_notes=ledger_notes,
        )

    # --- (3) fast-check only, no native target ----------------------------
    if not targets:
        return FuzzScanResult(
            findings=findings,
            status="ok",
            notes="fuzz: fast-check present (detect-only); no native targets",
            ledger_notes=ledger_notes,
        )

    # --- (4) native present but not opted in ------------------------------
    if not opt_in:
        ledger_notes.append(
            f"fuzz: {len(targets)} native fuzz target(s) present but not opted in "
            "(--fuzz); native engines not invoked"
        )
        return FuzzScanResult(
            findings=findings,
            status="unavailable",
            notes=(
                f"fuzz: {len(targets)} native fuzz target(s) detected; opt in with "
                "--fuzz to run them under the wall-clock budget"
            ),
            ledger_notes=ledger_notes,
        )

    # --- (5) opt-in native run (budgeted, tripwired) ----------------------
    statuses: list[str] = []
    for target in targets:
        try:
            t_findings, t_status, t_notes = _run_native_target(
                target,
                repo,
                base_env=env,
                budget_seconds=float(cfg.budget_seconds),
            )
        except Exception as exc:  # noqa: BLE001 — a target never crashes the lane
            t_findings, t_status, t_notes = (
                [],
                "unavailable",
                [f"fuzz: target {target.path} failed: {type(exc).__name__}: {exc}"],
            )
        findings.extend(t_findings)
        statuses.append(t_status)
        ledger_notes.extend(t_notes)

    status = _derive_status(statuses)
    return FuzzScanResult(
        findings=findings,
        status=status,
        notes=f"fuzz: {len(targets)} native target(s) run; {len(findings)} finding(s)",
        ledger_notes=ledger_notes,
    )


# Naming variant the Wave-0 candidate test tolerates.
candidates = candidate_surfaces

__all__ = [
    "FuzzConfig",
    "read_fuzz_config",
    "FuzzEngine",
    "FuzzTarget",
    "FuzzScanResult",
    "FuzzStatus",
    "FuzzDetectResult",
    "CrashSummary",
    "fastcheck_present",
    "native_targets",
    "candidate_surfaces",
    "parse_libfuzzer_crashes",
    "build_crash_findings",
    "run_fuzz",
    "detect",
    "candidates",
]
