"""ARCH-02 jscpd JSON→Finding map contract (Plan 14-03, Wave-2).

SKIPPED until ``architecture.jscpd_json`` lands. Pins the pure-mapping contract
over the REAL recorded fixture: ONE aggregate Finding (never per-clone-pair), the
duplication floor (<5% → no finding), the severity bands (>20%→major,
5–20%→minor), the top-N=10 hotspot cap ranked by ``lines`` desc, and
verify-phrasing.
"""
from __future__ import annotations

import pytest

jscpd_json = pytest.importorskip(
    "repo_audit.adapters.architecture.jscpd_json",
    reason="Wave 2 (Plan 03) not yet landed — architecture.jscpd_json missing",
)

from repo_audit.adapters.supabase.verify_phrasing import (  # noqa: E402
    assert_verify_phrasing,
)


def _report(percentage, duplicates=None):
    """Build a minimal jscpd report dict with a given duplication percentage."""
    return {
        "statistics": {
            "total": {
                "lines": 100,
                "tokens": 1000,
                "sources": 4,
                "clones": len(duplicates or []),
                "duplicatedLines": int(percentage),
                "duplicatedTokens": 0,
                "percentage": percentage,
                "percentageTokens": percentage,
            }
        },
        "duplicates": duplicates or [],
    }


def _dup(lines, first="src/a.js", second="src/b.js"):
    return {
        "format": "javascript",
        "lines": lines,
        "tokens": 0,
        "firstFile": {"name": first, "start": 1, "end": lines},
        "secondFile": {"name": second, "start": 1, "end": lines},
    }


def test_one_aggregate_finding_never_per_clone(load_json) -> None:
    """statistics.total → exactly ONE aggregate Finding (never per clone-pair)."""
    findings = jscpd_json.map_jscpd_json(load_json("jscpd"), floor_pct=5)
    assert len(findings) == 1
    assert findings[0].rule_id == "duplication_summary"
    assert findings[0].dimension == "architecture_rot"


def test_floor_suppresses_below_5pct() -> None:
    """percentage < floor → NO finding (the number lives in summary only)."""
    findings = jscpd_json.map_jscpd_json(_report(4.9, [_dup(10)]), floor_pct=5)
    assert findings == []


@pytest.mark.parametrize(
    "percentage, expected",
    [(50.0, "major"), (21.0, "major"), (20.0, "minor"), (6.0, "minor")],
)
def test_severity_bands(percentage, expected) -> None:
    """>20% → major; 5–20% → minor."""
    findings = jscpd_json.map_jscpd_json(
        _report(percentage, [_dup(10)]), floor_pct=5
    )
    assert findings[0].severity == expected


def test_top_n_hotspots_capped_and_ranked() -> None:
    """Hotspots capped at 10, ranked by `lines` desc, cite first/second file."""
    dups = [_dup(lines=i, first=f"src/a{i}.js", second=f"src/b{i}.js") for i in range(1, 16)]
    findings = jscpd_json.map_jscpd_json(_report(50.0, dups), floor_pct=5)
    hotspots = findings[0].evidence.parsed_value["top_hotspots"]
    assert len(hotspots) == 10
    line_vals = [h["lines"] for h in hotspots]
    assert line_vals == sorted(line_vals, reverse=True)
    assert line_vals[0] == 15  # the largest clone ranks first
    assert "first" in hotspots[0] and "second" in hotspots[0]


def test_findings_are_static_candidate_and_verify_phrased(load_json) -> None:
    """The aggregate Finding is static/candidate and passes verify-phrasing."""
    findings = jscpd_json.map_jscpd_json(load_json("jscpd"), floor_pct=5)
    for f in findings:
        assert f.evidence_type == "static"
        assert f.confidence == "candidate"
    assert_verify_phrasing(findings)  # raises on a banned runtime-certainty word
