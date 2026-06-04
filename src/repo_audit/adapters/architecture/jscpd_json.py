"""jscpd ``--reporters json`` → ONE aggregate Finding (Phase 14, Plan 03, ARCH-02).

A tiny, dedicated transform — NOT a fork of ``sarif_to_findings`` (jscpd emits no
SARIF). jscpd writes ``statistics.total`` describing the repo-wide copy-paste
duplication, plus a ``duplicates[]`` array of individual clone pairs. This module
collapses ``statistics.total`` into **exactly ONE aggregate** ``architecture_rot``
Finding per scan — never one-per-clone-pair.

That adapter-side aggregation + reporting floor is the **D-14-03 deliberate
divergence** from Phase 13's faithful-emit stance (D-13-04). It is **explicitly
authorized by SC2** (the SC2 "counted summary" disposition): a per-clone-pair flood
would drown the report, so the headline is one summary Finding and the offending
clone pairs are surfaced as a bounded top-N hotspot list inside its
``parsed_value``. This is INTENTIONAL — it does not contradict the
faithful-per-finding posture of the SARIF tools; duplication is a single
repo-level metric, not a set of discrete issues.

The map MIRRORS the single-aggregate Evidence/Finding shape of
``adapters/typescript/parsers/lcov.py`` (the ``coverage_summary`` analog — it does
NOT import ``sarif/parser.py``), reading the native jscpd JSON keys pinned by
``tests/adapters/architecture/fixtures/jscpd/sample.json``.

Contract (RESEARCH lines 467-489):
  * Headline metric = ``statistics.total.percentage`` — duplicated **LINES** %,
    NOT ``percentageTokens`` (Pitfall 3: token counts are unreliable).
  * **Floor gate:** ``percentage < floor_pct`` (default 5) → ``[]`` (NO finding).
    The number still surfaces — the *collector* puts it in the result notes
    (SAFE-08 disclosure), not a finding.
  * **Severity ladder:** ``> 20%`` → ``major``; ``5–20%`` → ``minor``. Both are
    allowed at ``confidence='candidate'`` (SCH-04 caps only critical/blocker), so
    the candidate cap NEVER demotes the faithful severity.
  * ``evidence_type='static'`` (SAFE-01 — a static token analysis, never runtime),
    ``confidence='candidate'`` (D-06-03; Phase 17 corroboration promotes),
    ``source_tool='jscpd'``, ``rule_id='duplication_summary'``.
  * **Top-N hotspots** (default 10) from ``duplicates[]`` ranked by per-entry
    ``lines`` DESC (NOT ``tokens`` — Pitfall 3), each citing ``firstFile.name`` /
    ``secondFile.name`` / ``lines`` / ``span``.

Recommendations use VERIFY-phrasing (the knip / depcruise style): they say
"verify" and NEVER carry a runtime-certainty word (enforced/secure/protected), so
the shared CRIT-4 ``assert_verify_phrasing`` tripwire does not raise.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "jscpd"
_RULE_ID = "duplication_summary"
_DEFAULT_DIMENSION = "architecture_rot"

# The duplicated-LINES % below which no finding fires (D-14-03; overridable per-repo
# via .repo-audit.yaml SC4). The number still appears in the collector notes.
_DEFAULT_FLOOR_PCT = 5

# The top-N clone-pair hotspots cited inside the aggregate finding's parsed_value,
# ranked by per-entry `lines` descending (Pitfall 3: per-clone tokens unreliable).
_DEFAULT_TOP_N = 10

# The single severity-band threshold (RESEARCH lines 141-152): strictly above this
# is `major`; at-or-below (down to the floor) is `minor`. Both allowed at candidate.
_MAJOR_THRESHOLD_PCT = 20

# Verify-phrasing recommendation (knip / depcruise _CANDIDATE_RECOMMENDATION style;
# SC3 / SAFE-05). Says "verify"; carries NO runtime-certainty word
# (enforced/secure/protected) so the CRIT-4 assert_verify_phrasing tripwire never
# raises.
_CANDIDATE_RECOMMENDATION: str = (
    "Copy-paste duplication hotspots present — verify the cited clone pairs "
    "(first <-> second) by inspecting the shared blocks before extracting a "
    "shared module; jscpd flags textual repetition, not semantic equivalence."
)


def _severity_for(overall_pct: float) -> str:
    """Faithful duplication severity band (RESEARCH lines 141-152).

    ``> 20%`` → ``major``; ``5–20%`` (down to the floor) → ``minor``. ``major`` is
    the ceiling, so the SCH-04 candidate cap (which bites only at critical/blocker)
    is NEVER tripped — the faithful severity is preserved, never demoted.
    """
    return "major" if overall_pct > _MAJOR_THRESHOLD_PCT else "minor"


def _hotspots(duplicates: list[dict[str, Any]], top_n: int) -> list[dict[str, Any]]:
    """The top-N clone-pair hotspots, ranked by per-entry ``lines`` DESC.

    Ranking uses ``lines`` NOT ``tokens`` (per-entry token counts are unreliable —
    Pitfall 3). Each hotspot cites the offending ``firstFile.name`` /
    ``secondFile.name``, its ``lines``, and a human-readable ``span``. Capped at
    ``top_n``.
    """
    ranked = sorted(
        duplicates,
        key=lambda d: d.get("lines") or 0,
        reverse=True,
    )[: max(top_n, 0)]
    hotspots: list[dict[str, Any]] = []
    for d in ranked:
        first = (d.get("firstFile") or {}).get("name") or ""
        second = (d.get("secondFile") or {}).get("name") or ""
        lines = d.get("lines") or 0
        first_start = (d.get("firstFile") or {}).get("start")
        first_end = (d.get("firstFile") or {}).get("end")
        span = (
            f"{first_start}-{first_end}"
            if first_start is not None and first_end is not None
            else ""
        )
        hotspots.append(
            {
                "first": first,
                "second": second,
                "lines": lines,
                "span": span,
            }
        )
    return hotspots


def jscpd_statistics_to_finding(
    report: dict[str, Any],
    *,
    default_dimension: str = _DEFAULT_DIMENSION,
    floor_pct: float = _DEFAULT_FLOOR_PCT,
    top_n: int = _DEFAULT_TOP_N,
    severity_map: dict[str, str] | None = None,  # noqa: ARG001 — reserved for parity
) -> list[Finding]:
    """Collapse ``statistics.total`` into EXACTLY 0 or 1 aggregate Finding.

    Args:
        report: the parsed jscpd JSON document
            (``{statistics:{total:{percentage,...}}, duplicates:[...]}``).
        default_dimension: the routed dimension (``architecture_rot`` by default;
            resolved from ``adapter.yaml`` by the caller).
        floor_pct: the duplicated-LINES % below which NO finding fires (default 5;
            overridable per-repo via ``.repo-audit.yaml`` SC4). The number
            still surfaces — the collector puts it in its notes (SAFE-08).
        top_n: cap on the cited clone-pair hotspots (default 10), ranked by
            ``lines`` desc.
        severity_map: reserved for call-site parity with the depcruise map; the
            duplication severity is derived from the single percentage band, so
            this is intentionally unused (the parameter keeps the two architecture
            maps call-compatible).

    Returns:
        ``[]`` when ``percentage < floor_pct`` (below-floor — no finding); otherwise
        a list with EXACTLY ONE static/candidate ``architecture_rot`` Finding citing
        the overall percentage + the top-N hotspots. NEVER one-per-clone-pair
        (D-14-03 / SC2). Recommendation passes ``assert_verify_phrasing``.
    """
    total = ((report or {}).get("statistics") or {}).get("total") or {}
    overall_pct = total.get("percentage")
    if overall_pct is None:
        # No headline metric — nothing to summarize (treated as below-floor).
        return []

    if overall_pct < floor_pct:
        # Below the reporting floor → NO finding. The number is surfaced by the
        # collector's notes (SAFE-08), never as a finding.
        return []

    severity = _severity_for(overall_pct)
    duplicates = (report or {}).get("duplicates") or []
    hotspots = _hotspots(duplicates, top_n)

    snippet = (
        f"jscpd: {overall_pct}% duplicated lines across "
        f"{total.get('sources', '?')} source(s), "
        f"{total.get('clones', len(duplicates))} clone(s)"
    )

    evidence = Evidence(
        tool=_SOURCE_TOOL,
        output_snippet=snippet,
        parsed_value={
            "overall_pct": overall_pct,
            "overall_pct_tokens": total.get("percentageTokens"),
            "total_clones": total.get("clones", len(duplicates)),
            "duplicated_lines": total.get("duplicatedLines"),
            "total_lines": total.get("lines"),
            "floor_pct": floor_pct,
            "faithful_severity": severity,
            "top_hotspots": hotspots,
        },
    )
    return [
        Finding(
            dimension=default_dimension,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            file=None,
            line=None,
            evidence=evidence,
            evidence_type="static",
            confidence="candidate",
            recommendation=_CANDIDATE_RECOMMENDATION,
            source_tool=_SOURCE_TOOL,
            rule_id=_RULE_ID,
            confidence_caveat=None,
        )
    ]


def map_jscpd_json(
    report: dict[str, Any],
    *,
    default_dimension: str = _DEFAULT_DIMENSION,
    floor_pct: float = _DEFAULT_FLOOR_PCT,
    top_n: int = _DEFAULT_TOP_N,
    severity_map: dict[str, str] | None = None,
) -> list[Finding]:
    """Map a full jscpd JSON document to its single aggregate Finding (or ``[]``).

    The public entry point the collector and the contract tests call. A thin
    delegate to :func:`jscpd_statistics_to_finding` so the two architecture maps
    (``map_depcruise_json`` / ``map_jscpd_json``) read symmetrically. A missing
    ``statistics.total.percentage`` or a below-floor percentage → ``[]``.
    """
    return jscpd_statistics_to_finding(
        report,
        default_dimension=default_dimension,
        floor_pct=floor_pct,
        top_n=top_n,
        severity_map=severity_map,
    )


__all__ = [
    "jscpd_statistics_to_finding",
    "map_jscpd_json",
]
