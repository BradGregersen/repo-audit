"""kover JaCoCo-XML aggregate coverage finding (TST-01).

When to use: when narrating the ``test_integrity`` dimension for a Kotlin
stack whose coverage comes from kover's ``koverXmlReport`` task. kover emits
JaCoCo-format XML (NOT lcov — 11-RESEARCH Pitfall 9) at
``build/reports/kover/report.xml``. This parser reads the REPORT-ROOT
direct-child ``<counter>`` elements (the whole-project totals — RESEARCH
Assumption A3), NOT a nested ``<package>`` counter, and emits a single
``test_integrity`` aggregate Finding whose ``parsed_value`` mirrors the lcov
parser's shape (``{total_pct, line_pct, branch_pct, function_pct, file_count,
artifact_mtime_iso}``).

Coverage is reported as a METRIC ("X% line coverage executed"), never a
pass/fail verdict (MOD-4). Numbers MUST come from this Finding's parsed_value;
the faithfulness gate strips invented percentages.

XML is parsed through ``repo_audit.adapters.safe_xml.parse_xml``
(defusedxml) — the XXE-safe seam (threat T-11-03-02). The standard-library
tree parser is deliberately NOT imported (grep-banned).

When NOT to use: when no kover artifact exists or it is stale — the Finding
is present with ``evidence_type='unavailable'``; narrate the gap honestly
rather than guessing a percentage.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repo_audit.adapters.safe_xml import parse_xml
from repo_audit.schema.finding import Evidence, Finding

# D-43 staleness indirection — reuse the lcov parser's CONFIG-backed helper so
# the same ``.repo-audit.yaml: coverage_staleness_hours`` overlay applies
# uniformly to lcov AND kover coverage artifacts.
from repo_audit.adapters.typescript.parsers.lcov import _get_staleness_hours

# 11-RESEARCH Pitfall 9: kover's koverXmlReport writes the JaCoCo report here.
KOVER_RELATIVE_PATH: str = "build/reports/kover/report.xml"

# SAFE-01 ethos: a static artifact carries a runtime caveat (the suite was not
# necessarily re-executed for this read). Mirrors lcov._COVERAGE_CAVEAT.
_COVERAGE_CAVEAT: str = (
    "Coverage is computed from a static kover JaCoCo artifact; the test suite "
    "was not re-executed for this read. Stale artifacts may misrepresent "
    "current code."
)


def _resolve_report_path(path: Path) -> Path:
    """Resolve the kover report.xml path from either a repo root or a direct file.

    Callers pass either the target repo root (then append ``KOVER_RELATIVE_PATH``)
    or a direct path to the ``report.xml`` file. A path that names an ``.xml``
    file is treated as the direct artifact; anything else is treated as a repo
    root and the conventional kover relative path is appended.
    """
    p = Path(path)
    if p.suffix.lower() == ".xml":
        return p
    return p / KOVER_RELATIVE_PATH


def parse_kover_xml(repo_path: Path) -> list[Finding]:
    """Return the kover aggregate Finding (or an unavailable Finding).

    Always returns exactly one Finding so the Test & Verification section has a
    stable row count regardless of repo state:

        * missing OR stale report.xml → ``evidence_type='unavailable'``,
          ``reason='stale_or_missing_coverage_artifact'``
        * malformed / XXE / DTD XML    → ``evidence_type='unavailable'``,
          ``reason='kover_parse_failed'``
        * fresh + valid report.xml     → ``evidence_type='static'`` with
          ``line_pct/branch_pct/function_pct/file_count/artifact_mtime_iso``

    Never raises across the function boundary (mirrors lcov.parse_from_repo).
    """
    report = _resolve_report_path(repo_path)
    if not report.is_file():
        return [
            _kover_unavailable(
                reason="stale_or_missing_coverage_artifact",
                detail=f"{KOVER_RELATIVE_PATH} not found",
            )
        ]

    mtime = report.stat().st_mtime
    age_seconds = time.time() - mtime
    staleness_hours = _get_staleness_hours()  # D-43 indirection (shared with lcov)
    if age_seconds > staleness_hours * 3600:
        return [
            _kover_unavailable(
                reason="stale_or_missing_coverage_artifact",
                detail=(
                    f"{KOVER_RELATIVE_PATH} mtime older than "
                    f"{staleness_hours}h ({age_seconds / 3600.0:.1f}h)"
                ),
            )
        ]

    try:
        # safe_xml.parse_xml returns the root Element; raises
        # EntitiesForbidden/DTDForbidden/ExternalReferenceForbidden/ParseError
        # on hostile or malformed input. Catch broadly → unavailable.
        root = parse_xml(report)
        totals = _extract_root_counters(root)
    except Exception as e:  # noqa: BLE001 — hostile/malformed XML handling per T-11-03-02
        return [
            _kover_unavailable(
                reason="kover_parse_failed",
                detail=f"{type(e).__name__}: {e}",
            )
        ]

    snippet = _summary_snippet(totals)
    return [
        Finding(
            dimension="test_integrity",
            severity="major",
            evidence_type="static",
            confidence="high",
            source_tool="kover",
            source_collector="kotlin_adapter",
            rule_id="coverage_summary",
            recommendation=(
                f"{totals['line_pct']}% line coverage executed via "
                f"koverXmlReport ({totals['branch_pct']}% branch, "
                f"{totals['function_pct']}% method); refresh by running "
                "`./gradlew koverXmlReport`."
            ),
            confidence_caveat=_COVERAGE_CAVEAT,
            evidence=Evidence(
                tool="kover-xml-parser",
                output_snippet=snippet,
                parsed_value={
                    "total_pct": totals["line_pct"],  # alias for trend convenience
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


def _extract_root_counters(root: Any) -> dict[str, Any]:
    """Read the REPORT-ROOT direct-child counters (RESEARCH A3 / Pitfall 9).

    Iterates ``root.findall("counter")`` — DIRECT children only, NOT a
    recursive descendant walk — so the whole-project total is read, never a
    nested ``<package>`` counter. JaCoCo emits ``LINE``/``BRANCH``/``METHOD``
    (and ``INSTRUCTION``/``CLASS``) counters; we surface LINE→line_pct,
    BRANCH→branch_pct, METHOD→function_pct.

    file_count is the count of ``<sourcefile>`` elements if present (cheap),
    else the ``<class>`` element count, else 0.
    """
    pcts = {"LINE": 0.0, "BRANCH": 0.0, "METHOD": 0.0}
    for c in root.findall("counter"):
        ctype = c.get("type")
        if ctype not in pcts:
            continue
        covered = int(c.get("covered", "0"))
        missed = int(c.get("missed", "0"))
        denom = covered + missed
        pcts[ctype] = round(100.0 * covered / denom, 1) if denom else 0.0

    file_count = len(root.findall(".//sourcefile")) or len(root.findall(".//class"))

    return {
        "line_pct": pcts["LINE"],
        "branch_pct": pcts["BRANCH"],
        "function_pct": pcts["METHOD"],
        "file_count": file_count,
    }


def _summary_snippet(totals: dict[str, Any]) -> str:
    """Path-free, low-entropy one-line coverage summary for Evidence.output_snippet.

    Built from the already-computed totals so every number traces back to
    parsed_value (faithful). Mirrors lcov._summary_snippet so the secret-lint
    entropy backstop sees the same benign shape.
    """
    return (
        f"kover: {totals['line_pct']}% line, "
        f"{totals['branch_pct']}% branch, "
        f"{totals['function_pct']}% method "
        f"across {totals['file_count']} files"
    )


def _kover_unavailable(*, reason: str, detail: str) -> Finding:
    """Missing / stale / malformed kover coverage ⇒ unavailable Finding.

    Mirrors ``lcov._unavailable_finding`` but ``source_tool='kover'``.
    """
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="unavailable",
        confidence="medium",
        source_tool="kover",
        source_collector="kotlin_adapter",
        rule_id="coverage_unavailable",
        recommendation=(
            "Run `./gradlew koverXmlReport` to produce "
            "build/reports/kover/report.xml."
        ),
        evidence=Evidence(
            tool="kover-xml-parser",
            output_snippet=detail,
            parsed_value={"reason": reason, "detail": detail},
        ),
    )


__all__ = [
    "KOVER_RELATIVE_PATH",
    "parse_kover_xml",
]
