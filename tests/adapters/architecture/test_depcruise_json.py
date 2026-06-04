"""ARCH-01 depcruise JSON→Finding map contract (Plan 14-02, Wave-1).

SKIPPED until ``architecture.depcruise_json`` lands. Pins the pure-mapping
contract over the REAL recorded fixture: severity map (error→major / warn→minor
/ info→info, never tripping the SCH-04 critical/blocker cap), from/to/cycle
citation, verify-phrasing, and the static/candidate stamping.
"""
from __future__ import annotations

import pytest

depcruise_json = pytest.importorskip(
    "repo_audit.adapters.architecture.depcruise_json",
    reason="Wave 1 (Plan 02) not yet landed — architecture.depcruise_json missing",
)

from repo_audit.adapters.supabase.verify_phrasing import (  # noqa: E402
    assert_verify_phrasing,
)


def test_one_finding_per_violation_cites_from_to_cycle(load_json) -> None:
    """Each summary.violations[] → one Finding citing from/to + the cycle chain."""
    doc = load_json("dependency-cruiser")
    findings = depcruise_json.map_depcruise_json(doc)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "no-circular"
    assert f.file == "src/a.js"
    pv = f.evidence.parsed_value
    assert pv["from"] == "src/a.js"
    assert pv["to"] == "src/b.js"
    assert pv["cycle"] == ["src/b.js", "src/a.js"]


@pytest.mark.parametrize(
    "tool_severity, expected",
    [("error", "major"), ("warn", "minor"), ("info", "info")],
)
def test_severity_map_never_trips_sch04(tool_severity, expected) -> None:
    """error→major / warn→minor / info→info; error tops at major (no cap)."""
    doc = {
        "summary": {
            "violations": [
                {
                    "type": "cycle",
                    "from": "src/x.js",
                    "to": "src/y.js",
                    "rule": {"severity": tool_severity, "name": "no-circular"},
                    "cycle": [
                        {"name": "src/y.js"},
                        {"name": "src/x.js"},
                    ],
                }
            ],
            "error": 1,
            "warn": 0,
            "info": 0,
        }
    }
    findings = depcruise_json.map_depcruise_json(doc)
    assert findings[0].severity == expected
    # SCH-04: no candidate finding may carry critical/blocker.
    assert findings[0].severity not in {"critical", "blocker"}


def test_findings_are_static_candidate(load_json) -> None:
    """Every depcruise Finding is evidence_type=static + confidence=candidate."""
    findings = depcruise_json.map_depcruise_json(load_json("dependency-cruiser"))
    for f in findings:
        assert f.evidence_type == "static"
        assert f.confidence == "candidate"


def test_verify_phrasing_passes(load_json) -> None:
    """Recommendations use verify-phrasing — the CRIT-4 tripwire must not raise."""
    findings = depcruise_json.map_depcruise_json(load_json("dependency-cruiser"))
    assert_verify_phrasing(findings)  # raises on a banned runtime-certainty word


def test_no_violations_yields_no_findings() -> None:
    """An empty summary.violations[] → no Findings (number lives in summary)."""
    doc = {"summary": {"violations": [], "error": 0, "warn": 0, "info": 0}}
    assert depcruise_json.map_depcruise_json(doc) == []
