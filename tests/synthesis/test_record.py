"""SYN-01 / T-18-01 — the candidate_token collision guard (the 17-04 regression).

Two findings sharing the SAME `build_finding_ref` (same source_tool/rule_id/
file/line) but differing factor inputs must receive DISTINCT PriorityScores,
dispatched by their distinct `candidate_token`. The sidecar must NEVER cross-
inherit a score on the non-unique display key — the verbatim 17-04 fix.
"""
from __future__ import annotations

from repo_audit.synthesis.record import PriorityScore
from repo_audit.synthesis.score import score_findings
from repo_audit.verification.record import build_finding_ref


def test_priorityscore_forbids_extra():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PriorityScore(finding_ref="a::b::c:1", bogus_field=1)  # type: ignore[call-arg]

    # candidate_token defaults to -1.
    ps = PriorityScore(finding_ref="a::b::c:1")
    assert ps.candidate_token == -1


def test_collision_findings_keep_distinct_scores(finding_factory, record_factory):
    # Two findings that COLLIDE on build_finding_ref (identical tool/rule/file/line)
    # but differ on the factor inputs (dimension + reachability).
    f0 = finding_factory(
        source_tool="osv", rule_id="CVE-X", file="pkg/a.ts", line=10,
        dimension="security", evidence_type="static", severity="major",
    )
    f1 = finding_factory(
        source_tool="osv", rule_id="CVE-X", file="pkg/a.ts", line=10,
        dimension="quality", evidence_type="heuristic", severity="major",
    )
    assert build_finding_ref(f0) == build_finding_ref(f1)  # they truly collide

    findings = [f0, f1]
    records = {
        0: record_factory(candidate_token=0, reachable=True),
        1: record_factory(candidate_token=1, reachable=None),
    }

    scores = score_findings(findings, records)

    # one score per candidate_token, keyed on the token (NOT the ref).
    assert set(scores.keys()) == {0, 1}
    # despite sharing build_finding_ref, the two scores are DISTINCT —
    # no cross-inheritance on the non-unique display key.
    assert scores[0].composite != scores[1].composite
    assert scores[0].candidate_token == 0
    assert scores[1].candidate_token == 1
    # both carry the SAME (non-unique) finding_ref but distinct identities.
    assert scores[0].finding_ref == scores[1].finding_ref
