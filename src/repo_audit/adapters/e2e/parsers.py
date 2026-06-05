"""E2E result + best-effort coverage parsers (E2E-01 / D-16-03, Plan 16-02 — Task 2).

Parses Playwright JSON and Maestro/Detox JUnit XML into pass/fail tallies and
Findings, plus a STRICTLY best-effort V8 coverage reader. Two hard contracts:

  * XML is parsed ONLY through ``safe_xml.parse_xml`` (defusedxml) — NEVER any
    unsafe stdlib XML parser (CLAUDE.md mandate; T-16-02-02). A malformed /
    hostile document → the caller maps the refusal to unavailable.
  * Coverage is best-effort: ``read_v8_coverage`` reads an ALREADY-EMITTED
    artifact only; absent → ``None`` (NEVER instruments, NEVER fabricates a
    number — D-16-03 / T-16-02-04).

Findings route to the ``test_integrity`` dimension (Claude's discretion per
CONTEXT), ``evidence_type="static"`` (the tool's machine-readable output is
parsed, not a live runtime assertion), ``confidence="candidate"`` (SCH-04 caps
candidate below critical; Phase 17 is the sole promotion path), and
``source_tool`` in {"playwright","detox","maestro"}.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from repo_audit.adapters import safe_xml
from repo_audit.schema.finding import Evidence, Finding

_DIMENSION = "test_integrity"
_EVIDENCE_TYPE = "static"
_CONFIDENCE = "candidate"

# Conventional already-emitted V8 / coverage-summary artifacts. We read these if
# present; we NEVER create them (no instrumentation — D-16-03).
_V8_COVERAGE_RELS: tuple[str, ...] = (
    "coverage/coverage-summary.json",
    "coverage/coverage-final.json",
    "coverage/coverage-summary.json".replace("coverage/", "test-results/"),
)


def parse_playwright_json(stdout_or_path: str | os.PathLike[str]) -> tuple[int, int, int]:
    """Parse a Playwright JSON report into ``(passed, failed, total)``.

    Reads the per-test result status from
    ``suites[].specs[].tests[].results[].status``. Accepts either the JSON text
    (typically Playwright's stdout) or a path to a report file. NEVER raises a
    parse error to the caller — an unparseable / unexpected shape yields
    ``(0, 0, 0)`` so the envelope can degrade honestly.
    """
    try:
        if isinstance(stdout_or_path, os.PathLike) or (
            isinstance(stdout_or_path, str)
            and "\n" not in stdout_or_path
            and "{" not in stdout_or_path
            and Path(stdout_or_path).is_file()
        ):
            text = Path(os.fspath(stdout_or_path)).read_text(encoding="utf-8")
        else:
            text = str(stdout_or_path)
        report = json.loads(text)
    except (OSError, ValueError, TypeError):
        return (0, 0, 0)

    passed = 0
    failed = 0
    try:
        for suite in report.get("suites", []) or []:
            for spec in suite.get("specs", []) or []:
                for test in spec.get("tests", []) or []:
                    for result in test.get("results", []) or []:
                        status = result.get("status")
                        if status == "passed":
                            passed += 1
                        elif status in ("failed", "timedOut", "interrupted"):
                            failed += 1
    except (AttributeError, TypeError):
        return (0, 0, 0)
    return (passed, failed, passed + failed)


def parse_junit(path: str | os.PathLike[str]) -> tuple[int, int, int]:
    """Parse a Maestro / Detox JUnit XML report into ``(passed, failed, total)``.

    Uses ``safe_xml.parse_xml`` (defusedxml) — NEVER an unsafe stdlib parser (T-16-02-02).
    A ``<testcase>`` carrying an ``<error>`` or ``<failure>`` child counts as a
    failure; otherwise a pass. Lets defusedxml refusals / parse errors propagate
    to the caller, which maps them to ``status="unavailable"`` (the safe-XML
    contract) — a hostile document is NEVER expanded.
    """
    root = safe_xml.parse_xml(path)
    passed = 0
    failed = 0
    for testcase in root.iter("testcase"):
        is_failure = (
            testcase.find("failure") is not None
            or testcase.find("error") is not None
        )
        if is_failure:
            failed += 1
        else:
            passed += 1
    return (passed, failed, passed + failed)


def read_v8_coverage(repo: Path, td: Optional[Path] = None) -> float | None:
    """Best-effort line-coverage percent from an ALREADY-EMITTED artifact (D-16-03).

    Reads a conventional coverage-summary JSON the harness may already have
    written; returns the total line-coverage percent if found, else ``None``.
    NEVER instruments the repo and NEVER fabricates a number — absence is
    honestly reported as ``None`` (T-16-02-04). ``td`` is an optional scratch
    dir (caller's tempdir) checked first; the target repo is checked best-effort.
    """
    search_roots: list[Path] = []
    if td is not None:
        search_roots.append(Path(td))
    search_roots.append(Path(repo))

    for root in search_roots:
        for rel in _V8_COVERAGE_RELS:
            candidate = root / rel
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            pct = _extract_line_pct(data)
            if pct is not None:
                return pct
    return None


def _extract_line_pct(data: object) -> float | None:
    """Pull a total line-coverage percent from a coverage-summary-shaped dict.

    Handles the Istanbul ``coverage-summary.json`` shape
    (``{"total": {"lines": {"pct": <float>}}}``); returns ``None`` on any
    structural gap (never invents a number).
    """
    if not isinstance(data, dict):
        return None
    total = data.get("total")
    if not isinstance(total, dict):
        return None
    lines = total.get("lines")
    if not isinstance(lines, dict):
        return None
    pct = lines.get("pct")
    return float(pct) if isinstance(pct, (int, float)) else None


def build_result_finding(
    passed: int,
    failed: int,
    total: int,
    *,
    source_tool: str,
) -> Finding:
    """Build the aggregate pass/fail Finding for an E2E run (test_integrity).

    Severity is ``major`` when any test failed (a real, actionable signal capped
    at ``candidate`` by SCH-04 — Phase 17 promotes), else ``info``.
    """
    severity = "major" if failed > 0 else "info"
    return Finding(
        dimension=_DIMENSION,
        severity=severity,
        evidence=Evidence(
            tool=source_tool,
            output_snippet=f"E2E: {passed} passed, {failed} failed, {total} total",
            parsed_value={
                "passed": passed,
                "failed": failed,
                "total": total,
            },
        ),
        evidence_type=_EVIDENCE_TYPE,
        confidence=_CONFIDENCE,
        source_tool=source_tool,
        rule_id="e2e_passfail",
        recommendation=(
            "Investigate the failing E2E flow(s)."
            if failed > 0
            else "E2E suite passed."
        ),
    )


def build_coverage_finding(
    coverage_pct: float | None,
    *,
    source_tool: str,
) -> Finding:
    """Build a best-effort coverage Finding (D-16-03).

    A present percent → an ``info`` test_integrity Finding carrying the number;
    an absent artifact → an ``evidence_type="unavailable"`` Finding that states
    coverage was not measured (never a fabricated 0).
    """
    if coverage_pct is None:
        return Finding(
            dimension=_DIMENSION,
            severity="info",
            evidence=Evidence(
                tool=source_tool,
                output_snippet=(
                    "E2E coverage unavailable: no already-emitted coverage "
                    "artifact (repo NOT instrumented — D-16-03)"
                ),
                parsed_value={"coverage_pct": None},
            ),
            evidence_type="unavailable",
            confidence=_CONFIDENCE,
            source_tool=source_tool,
            rule_id="e2e_coverage",
            recommendation=(
                "Coverage is best-effort and was not available without "
                "instrumenting the repo."
            ),
        )
    return Finding(
        dimension=_DIMENSION,
        severity="info",
        evidence=Evidence(
            tool=source_tool,
            output_snippet=f"E2E line coverage: {coverage_pct:.1f}%",
            parsed_value={"coverage_pct": float(coverage_pct)},
        ),
        evidence_type=_EVIDENCE_TYPE,
        confidence=_CONFIDENCE,
        source_tool=source_tool,
        rule_id="e2e_coverage",
    )


__all__ = [
    "parse_playwright_json",
    "parse_junit",
    "read_v8_coverage",
    "build_result_finding",
    "build_coverage_finding",
]
