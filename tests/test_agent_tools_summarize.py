"""Bounded-aggregate tests for `_summarize`.

The finding-list getter tools previously json.dumps'd the ENTIRE finding list
as one tool-result blob; large collectors (knip dead-code output runs to
thousands of findings on a large monorepo) overflowed the SDK tool-result / context budget so the agent narrated
from counts alone. `_summarize` is the single deterministic aggregation path
that hard-bounds every finding-list getter's payload.

These tests assert the three locked guarantees from the plan/CONTEXT:
  - the serialized summary is size-bounded regardless of input cardinality;
  - counts_by_severity and counts_by_rule each sum to total;
  - top_n is ranked severity-desc then rule-frequency-desc with a
    deterministic, input-permutation-independent tie-break.

Finding objects are constructed like tests/test_schema.py (Evidence + the
SCH-08/SAFE-01/SCH-04 validators are honored: candidate confidence stays at
major/minor/info; critical+static would need a caveat — we sidestep that by
using evidence_type='heuristic' for the higher-severity synthetic findings).
"""
from __future__ import annotations

import json

import pytest

_tools = pytest.importorskip(
    "repo_audit.agent.tools",
    reason="Phase 4 agent.tools required",
)

from repo_audit.schema.finding import Evidence, Finding  # noqa: E402


def _mk(
    *,
    severity: str = "info",
    rule_id: str = "rule_a",
    file: str | None = "src/x.ts",
    line: int | None = 1,
    snippet: str = "snip",
    dimension: str = "quality",
) -> Finding:
    """Build a valid Finding. evidence_type='heuristic' keeps all 5 severities
    constructible (no critical+static caveat requirement, no candidate rung-cap
    since confidence='high')."""
    return Finding(
        dimension=dimension,
        severity=severity,
        file=file,
        line=line,
        evidence=Evidence(tool="x", output_snippet=snippet, parsed_value={}, line_range=None),
        evidence_type="heuristic",
        confidence="high",
        rule_id=rule_id,
    )


def test_summary_is_size_bounded():
    """5,000 synthetic findings across many rules/files/severities → top_n capped
    at TOP_N and the whole serialized summary stays small regardless of input."""
    sevs = ["blocker", "critical", "major", "minor", "info"]
    findings = [
        _mk(
            severity=sevs[i % 5],
            rule_id=f"rule_{i % 400}",
            file=f"src/dir{i % 137}/file{i}.ts",
            line=i,
            snippet="x" * 4000,  # over the 2048 schema cap — proves we don't re-expand
        )
        for i in range(5000)
    ]

    result = _tools._summarize(findings)

    assert len(result["top_n"]) <= _tools.TOP_N
    assert _tools.TOP_N == 12
    blob = json.dumps(result, default=str)
    assert len(blob) < 25_000, f"summary serialized to {len(blob)} chars — not bounded"


def test_counts_reconcile():
    """counts_by_severity and counts_by_rule each sum to total == len(input),
    even when counts_by_rule folds the long tail into __other__."""
    sevs = ["blocker", "critical", "major", "minor", "info"]
    findings = [
        _mk(severity=sevs[i % 5], rule_id=f"rule_{i % 300}", file=f"f{i}.ts", line=i)
        for i in range(2000)
    ]

    result = _tools._summarize(findings)

    assert result["total"] == 2000 == len(findings)
    assert sum(result["counts_by_severity"].values()) == result["total"]
    assert sum(result["counts_by_rule"].values()) == result["total"]


def test_ranking_severity_then_frequency():
    """top_n ordered severity-descending (blocker→info); within a severity tie,
    the more frequent rule_id ranks first."""
    findings: list[Finding] = []
    # 3 'major' findings of rule_common, 1 'major' of rule_rare.
    findings += [_mk(severity="major", rule_id="rule_common", file=f"c{i}.ts", line=i) for i in range(3)]
    findings += [_mk(severity="major", rule_id="rule_rare", file="r.ts", line=99)]
    # 1 blocker — must sort to the very front (most severe).
    findings += [_mk(severity="blocker", rule_id="rule_block", file="b.ts", line=1)]
    # some info noise after.
    findings += [_mk(severity="info", rule_id="rule_info", file=f"i{i}.ts", line=i) for i in range(2)]

    top = _tools._summarize(findings)["top_n"]

    # First entry is the blocker.
    assert top[0]["severity"] == "blocker"
    # Among the 'major' tier, rule_common (freq 3) precedes rule_rare (freq 1).
    majors = [t for t in top if t["severity"] == "major"]
    common_idx = next(i for i, t in enumerate(majors) if t["rule_id"] == "rule_common")
    rare_idx = next(i for i, t in enumerate(majors) if t["rule_id"] == "rule_rare")
    assert common_idx < rare_idx


def test_ranking_is_deterministic():
    """Same input → identical top_n; a SHUFFLED copy of the SAME findings yields
    the SAME top_n order (the sort key is fully value-derived, so order is
    input-permutation-independent)."""
    import random

    sevs = ["blocker", "critical", "major", "minor", "info"]
    findings = [
        _mk(severity=sevs[i % 5], rule_id=f"rule_{i % 7}", file=f"src/f{i}.ts", line=i)
        for i in range(80)
    ]

    first = _tools._summarize(findings)["top_n"]
    second = _tools._summarize(findings)["top_n"]
    assert first == second  # same input → same order

    shuffled = findings[:]
    random.Random(1234).shuffle(shuffled)
    third = _tools._summarize(shuffled)["top_n"]
    assert first == third, "top_n must be permutation-independent"


def test_empty_findings():
    """_summarize([]) → total 0, empty count maps, empty top_n (no crash)."""
    result = _tools._summarize([])
    assert result["total"] == 0
    assert sum(result["counts_by_severity"].values()) == 0
    assert result["counts_by_rule"] == {} or sum(result["counts_by_rule"].values()) == 0
    assert result["top_n"] == []
