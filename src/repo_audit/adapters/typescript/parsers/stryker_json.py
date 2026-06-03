"""StrykerJS mutation-report parser (TST-02, Phase 11 Wave 1).

PURE PARSER / TRANSFORM. This module reads an already-loaded StrykerJS
``mutation.json`` (mutation-testing-report-schema v1/v2) dict and turns it into
deterministic numbers + Findings. It NEVER invokes Stryker, NEVER touches the
filesystem, and NEVER raises on a partial / malformed-but-dict report.

WHY a computed score (11-RESEARCH Pitfall 2, VERIFIED): the schema has NO
top-level ``mutationScore`` field. The score is COMPUTED from per-file mutant
statuses::

    detected = count(status in {Killed, Timeout})
    valid    = count(status in {Killed, Survived, Timeout, NoCoverage})
    score    = round(100 * detected / valid, 1)   # 0.0 when valid == 0

``Ignored`` / ``CompileError`` / ``RuntimeError`` / ``Pending`` are EXCLUDED from
BOTH numerator and denominator — they are not "valid" mutants for scoring.

The INVOCATION half of TST-02 lives in Plan 05's run-step, NOT here:
    * D-11-05 hard timeout: Stryker is run through ``run_tool`` with
      ``timeout_seconds=1800`` (a wall-clock cap, NOT ``--timeoutMS`` which only
      bounds a single test run). On ``TIMED_OUT`` the run-step still reads the
      partial ``mutation.json`` Stryker has written so far and calls
      :func:`build_mutation_finding` with ``status="partial"`` — an HONEST
      partial score rather than nothing.
    * Mutation testing is OPT-IN and never default fleet-wide (it is expensive);
      Plan 05 gates it behind a flag and reads the threshold for
      :func:`weak_test_signal` from ``.repo-audit.yaml``.

This module is the unit-testable transform half (Wave-0 test
``tests/adapters/typescript/parsers/test_stryker_json.py`` asserts against the
recorded fixture).
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Evidence, Finding

# Pitfall 2 status sets. ``Ignored`` (and CompileError/RuntimeError/Pending) are
# deliberately ABSENT from both sets so they never enter the denominator.
_DETECTED: frozenset[str] = frozenset({"Killed", "Timeout"})
_VALID: frozenset[str] = frozenset({"Killed", "Survived", "Timeout", "NoCoverage"})

_SOURCE_TOOL = "stryker"
_DIMENSION = "test_integrity"


def _tally(mutants: Any) -> tuple[int, int]:
    """Return ``(detected, valid)`` for one file's mutant list.

    Guards a missing / non-list ``mutants`` value (partial report → no
    KeyError / no TypeError) by treating it as zero mutants.
    """
    detected = valid = 0
    if not isinstance(mutants, list):
        return (0, 0)
    for mutant in mutants:
        if not isinstance(mutant, dict):
            continue
        status = mutant.get("status")
        if status in _VALID:
            valid += 1
            if status in _DETECTED:
                detected += 1
    return (detected, valid)


def _score(detected: int, valid: int) -> float:
    """Pitfall-2 score: ``round(100*detected/valid, 1)``; ``0.0`` when no valid."""
    return round(100.0 * detected / valid, 1) if valid else 0.0


def compute_mutation_score(report: dict) -> float:
    """Compute the overall mutation score from per-file mutant statuses.

    The score is ``100 * detected / valid`` (Pitfall 2). ``Ignored`` and the
    other non-scoring statuses are excluded from BOTH counts. Returns ``0.0``
    when there are no valid mutants. Never raises on a partial report (missing
    ``files`` / missing ``mutants`` → counted as zero).
    """
    detected = valid = 0
    files = report.get("files") if isinstance(report, dict) else None
    if isinstance(files, dict):
        for fdata in files.values():
            if not isinstance(fdata, dict):
                continue
            d, v = _tally(fdata.get("mutants"))
            detected += d
            valid += v
    return _score(detected, valid)


def per_file_scores(report: dict) -> dict[str, dict]:
    """Return ``{path: {"detected", "valid", "score"}}`` for every file.

    Drives the D-11-06 WEAK-test gap signal (a per-file kill ratio strictly
    below the line-coverage ratio is the signal source). Never raises on a
    partial report.
    """
    out: dict[str, dict] = {}
    files = report.get("files") if isinstance(report, dict) else None
    if isinstance(files, dict):
        for path, fdata in files.items():
            mutants = fdata.get("mutants") if isinstance(fdata, dict) else None
            d, v = _tally(mutants)
            out[str(path)] = {"detected": d, "valid": v, "score": _score(d, v)}
    return out


def build_mutation_finding(report: dict, *, status: str = "ok") -> Finding:
    """Build the ONE aggregate mutation-score Finding (a METRIC, not a verdict).

    ``status="ok"`` for a complete run; ``status="partial"`` when the Plan-05
    run-step hit the D-11-05 hard timeout and read a partial ``mutation.json``
    (the score-so-far is still HONEST — it is computed from the mutants Stryker
    managed to evaluate). The recommendation is phrased as a metric, never a
    pass/fail verdict (MOD-4 spirit): we report the number, we do not condemn.

    Numbers come from :func:`compute_mutation_score` / :func:`per_file_scores`;
    the faithfulness gate (Phase 4) sources percentages from ``parsed_value``.
    """
    score = compute_mutation_score(report)
    per_file = per_file_scores(report)
    files_scored = len(per_file)
    valid_total = sum(entry["valid"] for entry in per_file.values())

    if status == "partial":
        recommendation = (
            f"Mutation score (PARTIAL): {score}% from {valid_total} mutant(s) "
            f"across {files_scored} file(s); the mutation run timed out, so this "
            "reflects the mutants tested before the cap — treat it as a floor, "
            "not the final score."
        )
    else:
        recommendation = (
            f"Mutation score: {score}% from {valid_total} mutant(s) across "
            f"{files_scored} file(s). A metric of test-suite kill strength; "
            "lower scores suggest assertions that don't catch injected faults."
        )

    snippet = (
        f"stryker: mutation_score={score}% "
        f"(valid={valid_total}, files={files_scored}, status={status})"
    )

    return Finding(
        dimension=_DIMENSION,
        severity="minor",  # never above major — a metric, not a verdict
        evidence_type="static",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="mutation",
        rule_id="mutation_score",
        recommendation=recommendation,
        evidence=Evidence(
            tool="stryker-json",
            output_snippet=snippet,
            parsed_value={
                "mutation_score": score,
                "files_scored": files_scored,
                "valid_mutants": valid_total,
                "run_status": status,
                "per_file": per_file,
            },
        ),
    )


def weak_test_signal(
    line_pct: float,
    mutation_score: float,
    coverage_finding_ref: dict | list | None,
    *,
    threshold: float = 25.0,
) -> Finding | None:
    """D-11-06: emit ONE WEAK-test SIGNAL Finding when coverage outruns mutation.

    When ``line_pct - mutation_score >= threshold`` the test suite EXECUTES a lot
    of code (high line coverage) but KILLS few mutants (low mutation score) — a
    classic "asserts too little" smell. We surface it as a SIGNAL to investigate,
    NOT a verdict that the tests are bad (MOD-4): high coverage + low kill rate
    can also mean the mutated code is genuinely hard to assert on.

    Returns ``None`` when the gap is below ``threshold`` (no signal). The
    ``threshold`` is overridable by the caller — Plan 05 reads it from
    ``.repo-audit.yaml``. ``coverage_finding_ref`` cross-links back to the
    coverage Finding (convention: ``parsed_value["cross_link"]`` — there is NO
    ``cross_link`` schema field; precedent ``sast/anon.py``).
    """
    gap = round(line_pct - mutation_score, 1)
    if line_pct - mutation_score < threshold:
        return None

    if isinstance(coverage_finding_ref, list):
        cross_link = list(coverage_finding_ref)
    elif coverage_finding_ref is None:
        cross_link = ["coverage_summary"]
    else:
        cross_link = [coverage_finding_ref]

    return Finding(
        dimension=_DIMENSION,
        severity="minor",
        evidence_type="static",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="mutation",
        rule_id="weak_tests",
        recommendation=(
            f"High line coverage ({line_pct}%) but a low mutation score "
            f"({mutation_score}%) — a {gap}-point gap suggests the test suite "
            "executes this code without asserting on its behaviour. Worth "
            "investigating which assertions to strengthen (a signal, not a "
            "verdict — some code is genuinely hard to mutation-test)."
        ),
        evidence=Evidence(
            tool="stryker-json",
            output_snippet=(
                f"weak-test signal: line {line_pct}% vs mutation {mutation_score}% "
                f"(gap {gap} >= threshold {threshold})"
            ),
            parsed_value={
                "line_pct": line_pct,
                "mutation_score": mutation_score,
                "gap": gap,
                "threshold": threshold,
                "cross_link": cross_link,
            },
        ),
    )


__all__ = [
    "compute_mutation_score",
    "per_file_scores",
    "build_mutation_finding",
    "weak_test_signal",
]
