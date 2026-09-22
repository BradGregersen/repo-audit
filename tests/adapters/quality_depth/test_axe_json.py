"""A11Y-01 runtime tier (Phase 15, Plan 02, Task 2) — axe_json mapper contract.

``map_axe_json`` collapses an axe-core results document into ONE quality Finding
per WCAG violation (NOT per node). Each Finding is runtime/candidate, severity
capped at ``major`` (the SCH-04 candidate cap never bites because the ladder
tops at major), carries the faithful impact + bounded node targets in
``parsed_value``, redacts raw ``node.html`` from the snippet, and self-enforces
verify-phrasing (the D-15-07 runtime-exemption trap: the shared CRIT-4 tripwire
EXEMPTS runtime, so the mapper must police itself).
"""
from __future__ import annotations

import re

import pytest

pytest.importorskip(
    "repo_audit.adapters.quality_depth.axe_json",
    reason="optional module repo_audit.adapters.quality_depth.axe_json not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters.quality_depth.axe_json import (  # noqa: E402
    map_axe_json,
    map_axe_violations,
)

_BANNED = re.compile(r"\b(enforced|secure|protected)\b", re.IGNORECASE)


def test_one_finding_per_violation(load_json) -> None:
    """The fixture's 2 violations → exactly 2 Findings (per-violation, not node)."""
    doc = load_json("axe_results.json")
    findings = map_axe_json(doc)
    assert len(findings) == 2


def test_map_axe_violations_alias_matches(load_json) -> None:
    """The map_axe_violations alias is the same per-violation entry point."""
    doc = load_json("axe_results.json")
    assert len(map_axe_violations(doc)) == len(map_axe_json(doc))


def test_runtime_candidate_quality_evidence(load_json) -> None:
    """Every axe Finding is dimension=quality, runtime, candidate, file/line None."""
    doc = load_json("axe_results.json")
    for f in map_axe_json(doc):
        assert f.dimension == "quality"
        assert f.evidence_type == "runtime"
        assert f.confidence == "candidate"
        assert f.file is None
        assert f.line is None
        assert f.source_tool == "axe-core"
        assert f.source_collector == "quality_depth"


def test_severity_ladder_caps_at_major(load_json) -> None:
    """critical/serious → major; never critical/blocker (SCH-04 cap never trips)."""
    doc = load_json("axe_results.json")
    by_rule = {f.rule_id: f for f in map_axe_json(doc)}
    # image-alt has impact=critical → severity major, faithful_impact preserved.
    img = by_rule["image-alt"]
    assert img.severity == "major"
    assert img.evidence.parsed_value["faithful_impact"] == "critical"
    # color-contrast has impact=serious → severity major.
    assert by_rule["color-contrast"].severity == "major"
    for f in map_axe_json(doc):
        assert f.severity in {"major", "minor", "info"}
        assert f.severity not in {"critical", "blocker"}


def test_explicit_severity_ladder_rungs() -> None:
    """Verify each impact band maps to the documented rung."""
    from repo_audit.adapters.quality_depth.axe_json import _axe_severity

    assert _axe_severity("critical") == "major"
    assert _axe_severity("serious") == "major"
    assert _axe_severity("moderate") == "minor"
    assert _axe_severity("minor") == "info"
    # Unknown / missing impact degrades to the lowest rung, never promotes.
    assert _axe_severity(None) == "info"
    assert _axe_severity("bogus") == "info"


def test_parsed_value_keys_and_node_bounds(load_json) -> None:
    """parsed_value carries the documented keys; node_targets bounded by TOP_N."""
    doc = load_json("axe_results.json")
    for f in map_axe_json(doc):
        pv = f.evidence.parsed_value
        assert set(pv) >= {
            "rule_id",
            "faithful_impact",
            "wcag_tags",
            "node_targets",
            "node_count",
        }
        assert len(pv["node_targets"]) <= 10
        assert isinstance(pv["node_count"], int)
        assert pv["node_count"] >= len(pv["node_targets"])


def test_node_targets_truncated_to_top_n() -> None:
    """A violation with > TOP_N nodes truncates node_targets but keeps node_count."""
    doc = {
        "violations": [
            {
                "id": "color-contrast",
                "impact": "serious",
                "tags": ["wcag2aa"],
                "help": "Elements must meet contrast thresholds",
                "helpUrl": "https://example.com/color-contrast",
                "nodes": [
                    {"html": f"<a>{i}</a>", "target": [f".n{i}"]}
                    for i in range(25)
                ],
            }
        ]
    }
    f = map_axe_json(doc)[0]
    pv = f.evidence.parsed_value
    assert len(pv["node_targets"]) == 10
    assert pv["node_count"] == 25


def test_redaction_no_raw_html_in_snippet(load_json) -> None:
    """output_snippet carries help text + helpUrl but NEVER the raw node.html."""
    doc = load_json("axe_results.json")
    for f in map_axe_json(doc):
        snippet = f.evidence.output_snippet
        assert "dequeuniversity.com" in snippet  # the helpUrl surfaces
        assert "<img" not in snippet
        assert "<a " not in snippet
        assert "muted-link" not in snippet  # a raw-html token must not leak


def test_recommendations_self_enforce_verify_phrasing(load_json) -> None:
    """Each recommendation contains 'verify', none of enforced/secure/protected.

    Asserted DIRECTLY here (NOT via assert_verify_phrasing, which exempts
    runtime) — this is the D-15-07 runtime-exemption trap the mapper must
    self-police.
    """
    doc = load_json("axe_results.json")
    for f in map_axe_json(doc):
        assert "verify" in f.recommendation.lower()
        assert _BANNED.search(f.recommendation) is None


def test_empty_violations_yields_no_findings() -> None:
    """No violations → empty list (honest absence, never raises)."""
    assert map_axe_json({"violations": []}) == []
    assert map_axe_json({}) == []
