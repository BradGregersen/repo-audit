"""D-39 lcov parser (file-reader branch) + D-41' refresh-failure helper.

Per D-42: Phase 3 reads ``coverage/lcov.info`` ONLY. Cobertura XML and
Kover XML ship in Phase 6 alongside their adapters.

Per D-43: staleness = lcov.info mtime > 24h wall clock; the threshold
flows through ``_get_staleness_hours()`` (the Phase 7 user-config seam)
so the integer 24 is NOT hard-coded into the comparison path.

Per D-44: one aggregate Finding per scan with line/branch/function pcts
+ file_count + artifact_mtime_iso. Per-file Findings are deferred to
Phase 7.

Per Pitfall 14: streaming read (``for line in f``), NOT a whole-file
slurp via ``Path``-method-that-returns-text, so multi-MB lcov.info
files don't pin memory.

Per T-03-10: parser only opens ``<repo_path>/coverage/lcov.info``.
Does NOT follow ``SF:`` paths from the file — those are only counted to
increment ``file_count``, never opened. The only path-data leakage
surface left is ``output_snippet`` (first 1024 chars of lcov.info),
which is bounded by D-02 (2048 cap) at the Evidence layer.

Per D-41' / Decision C: this module ALSO exports
``_refresh_failed_finding``, a helper invoked by plan 03-05's CLI
failure-synthesis path when the coverage-refresh runner (plan 03-06)
returns ``status in {'failed', 'timeout'}``. The synthesised Finding
uses ``evidence_type='failed'`` — the new Literal variant landed by
plan 03-01a Wave 0a — which means SCH-03 (D-17) does NOT trigger
(``failed != static``) and SCH-04 widened (D-51') does NOT trigger
(``confidence='medium' != 'candidate'``). Verified by the Wave-2 test
``test_refresh_failed_finding_constructs_under_extended_schema``.

This helper is the SOLE emitter of the
``coverage_refresh_failed`` rule_id in this module — pinned by
``test_refresh_failed_finding_is_sole_emitter_of_rule_id``.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from repo_audit.schema.finding import Evidence, Finding

if TYPE_CHECKING:
    # Avoid an import cycle at module load — plan 03-06's refresh.py
    # imports from here are one-way and the helper is duck-typed on
    # the RefreshResult attribute surface so a runtime import isn't
    # actually required.
    from repo_audit.adapters.typescript.refresh import RefreshResult


# D-43 default staleness threshold. The constant is the SAFETY-NET
# fallback for the indirection helper below — the live read path is
# ``_get_staleness_hours()`` which pulls from
# ``CONFIG['tools']['coverage_lcov']['staleness_hours']`` (loaded by
# the adapter package from ``adapter.yaml``). Phase 7's user-overlay
# loader updates CONFIG before the parser is called.
STALENESS_HOURS_DEFAULT: int = 24


def _get_staleness_hours() -> int:
    """Return the staleness threshold (hours) from adapter CONFIG.

    D-43 / Blocker 3 indirection: the parser MUST read through this
    helper so Phase 7's ``.repo-audit.yaml: coverage_staleness_hours: 48``
    user-overlay is a one-line swap (the overlay loader updates CONFIG
    before the parser is called).

    Falls back to ``STALENESS_HOURS_DEFAULT`` on any of:
        * adapter package not importable (test-import edge case)
        * CONFIG missing the expected nested keys
        * the value is not coercible to int
    """
    try:
        from repo_audit.adapters.typescript import CONFIG

        return int(CONFIG["tools"]["coverage_lcov"]["staleness_hours"])
    except (KeyError, ImportError, TypeError, ValueError):
        return STALENESS_HOURS_DEFAULT


# D-42 / CONTEXT: only this exact relative path is read in Phase 3.
LCOV_RELATIVE_PATH: str = "coverage/lcov.info"


# SCH-03-mandatory caveat for the fresh-aggregate Finding (severity='major',
# evidence_type='static'). SCH-03 only fires on critical+static, so the
# caveat is not strictly required here — but D-17 and the SAFE-01 ethos
# (static signals carry runtime caveats) apply uniformly.
_COVERAGE_CAVEAT: str = (
    "Coverage is computed from a static artifact; the test suite was not "
    "re-executed. Stale artifacts may misrepresent current code."
)


def parse_from_repo(repo_path: Path) -> list[Finding]:
    """Return the D-44 aggregate Finding (or an unavailable Finding per COV-04).

    Always returns exactly one Finding so the report's Test & Verification
    section has a stable row count regardless of repo state:

        * missing OR stale lcov.info  → ``evidence_type='unavailable'``,
          ``reason='stale_or_missing_coverage_artifact'``
        * malformed lcov.info         → ``evidence_type='unavailable'``,
          ``reason='lcov_parse_failed'``
        * fresh + valid lcov.info     → ``evidence_type='static'`` with
          ``line_pct/branch_pct/function_pct/file_count/artifact_mtime_iso``
    """
    repo = Path(repo_path)
    lcov = repo / LCOV_RELATIVE_PATH
    if not lcov.is_file():
        return [
            _unavailable_finding(
                reason="stale_or_missing_coverage_artifact",
                detail="coverage/lcov.info not found",
            )
        ]
    mtime = lcov.stat().st_mtime
    age_seconds = time.time() - mtime
    staleness_hours = _get_staleness_hours()   # D-43 indirection (Blocker 3)
    if age_seconds > staleness_hours * 3600:
        return [
            _unavailable_finding(
                reason="stale_or_missing_coverage_artifact",
                detail=(
                    f"coverage/lcov.info mtime older than "
                    f"{staleness_hours}h ({age_seconds / 3600.0:.1f}h)"
                ),
            )
        ]
    try:
        totals = _parse_streaming(lcov)
    except Exception as e:  # noqa: BLE001 — malformed input handling per COV-04
        return [
            _unavailable_finding(
                reason="lcov_parse_failed",
                detail=f"{type(e).__name__}: {e}",
            )
        ]
    snippet = _read_snippet(lcov)
    return [
        Finding(
            dimension="test_integrity",                  # D-48
            severity="major",                            # D-51 default
            evidence_type="static",                      # static — we read an artifact
            confidence="high",
            source_tool="lcov",
            source_collector="typescript_adapter",
            rule_id="coverage_summary",
            recommendation=(
                "Coverage from lcov.info; refresh by running the project's test "
                "suite (e.g., `npm test -- --coverage`)."
            ),
            confidence_caveat=_COVERAGE_CAVEAT,
            evidence=Evidence(
                tool="lcov-parser",
                output_snippet=snippet,                    # D-02 cap auto-applies
                parsed_value={
                    "total_pct": totals["line_pct"],        # alias for trend convenience
                    "line_pct": totals["line_pct"],
                    "branch_pct": totals["branch_pct"],
                    "function_pct": totals["function_pct"],
                    "file_count": totals["file_count"],
                    "artifact_mtime_iso": datetime.fromtimestamp(
                        mtime, tz=timezone.utc,
                    ).isoformat(),
                },
            ),
        )
    ]


def _parse_streaming(lcov: Path) -> dict[str, Any]:
    """Streaming LCOV parse — Pitfall 14 (no whole-file slurp on multi-MB files).

    Accumulates LF/LH/BRF/BRH/FNF/FNH across all per-file records and counts
    SF lines as file_count. All non-recognised prefixes are silently
    ignored (``TN:``, ``DA:``, ``FN:``, ``FNDA:``, ``BRDA:``,
    ``end_of_record``). Malformed numeric fields raise ``ValueError``,
    caught by ``parse_from_repo`` → unavailable Finding.
    """
    lf = lh = brf = brh = fnf = fnh = fc = 0
    with lcov.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            k, sep, v = line.partition(":")
            if not sep:
                continue
            if k == "SF":
                fc += 1
            elif k == "LF":
                lf += int(v)
            elif k == "LH":
                lh += int(v)
            elif k == "BRF":
                brf += int(v)
            elif k == "BRH":
                brh += int(v)
            elif k == "FNF":
                fnf += int(v)
            elif k == "FNH":
                fnh += int(v)

    def _pct(hit: int, total: int) -> float:
        return round(100.0 * hit / total, 1) if total > 0 else 0.0

    return {
        "line_pct": _pct(lh, lf),
        "branch_pct": _pct(brh, brf),
        "function_pct": _pct(fnh, fnf),
        "file_count": fc,
    }


def _read_snippet(lcov: Path) -> str:
    """First 1024 chars of lcov.info — bounded read for Evidence.output_snippet."""
    with lcov.open(encoding="utf-8", errors="replace") as f:
        return f.read(1024)


def _unavailable_finding(*, reason: str, detail: str) -> Finding:
    """COV-04: missing / stale / malformed coverage ⇒ unavailable Finding."""
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="unavailable",
        confidence="medium",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_unavailable",
        recommendation=(
            "Run the test suite with coverage enabled "
            "(e.g., `npm test -- --coverage`) to produce coverage/lcov.info."
        ),
        evidence=Evidence(
            tool="lcov-parser",
            output_snippet=detail,
            parsed_value={"reason": reason, "detail": detail},
        ),
    )


def _refresh_failed_finding(
    refresh_result: "RefreshResult",
    runner_command: list[str],
) -> Finding:
    """D-41' / Decision C: synthesise a Finding for a failed coverage-refresh.

    Called by plan 03-05's CLI failure-synthesis path (sub-step D) when
    ``refresh_result.status in {'failed', 'timeout'}``. The constructed
    Finding uses:

        * ``evidence_type='failed'`` — the new Literal variant from plan
          03-01a Wave 0a. SCH-03 (D-17) does NOT require a
          ``confidence_caveat`` because the gate is
          ``evidence_type == 'static'``.
        * ``confidence='medium'`` — SCH-04 widened (D-51') does NOT
          reject because the gate is ``confidence == 'candidate'``.
        * ``parsed_value`` carries the runner's already-bounded
          stderr_tail (plan 03-06 caps to ≤2KB at the
          ``_redact_tail`` boundary; this helper does NOT re-truncate),
          the runner argv, the duration, and the exit_code if surfaced
          by RefreshResult.

    Plan 03-05 appends the returned Finding to the merged findings list
    ALONGSIDE (NOT replacing) the prior ``unavailable`` Finding from
    ``parse_from_repo`` — the report shows both "no fresh artifact" and
    "we tried; here's why it failed."
    """
    # ``refresh_result.stderr_tail`` is bounded to ≤2KB by plan 03-06's
    # RefreshResult acceptance criterion; do NOT re-truncate here.
    exit_code: int | None = getattr(refresh_result, "exit_code", None)
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="failed",                      # plan 03-01a / Decision C
        confidence="medium",
        source_tool="coverage_refresh",
        source_collector="lcov",
        rule_id="coverage_refresh_failed",
        recommendation=(
            "Coverage refresh runner failed. Check the runner command "
            "and stderr summary; re-run `repo-audit scan --refresh-coverage` "
            "after fixing, or omit the flag to fall back to import-only."
        ),
        confidence_caveat=None,                      # SCH-03 not triggered (failed != static)
        evidence=Evidence(
            tool="coverage-refresh",
            output_snippet=refresh_result.stderr_tail,
            parsed_value={
                "reason": "coverage_refresh_failed",
                "runner_command": list(runner_command),
                "stderr_tail": refresh_result.stderr_tail,
                "exit_code": exit_code,
                "duration_ms": refresh_result.duration_ms,
            },
        ),
    )


__all__ = [
    "LCOV_RELATIVE_PATH",
    "STALENESS_HOURS_DEFAULT",
    "_get_staleness_hours",
    "_refresh_failed_finding",
    "_unavailable_finding",
    "parse_from_repo",
]
