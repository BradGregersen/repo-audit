"""SYN-02 — Top-N eligibility excludes candidates; never pads under-fill.

These tests target the selection symbol `synthesis.select`. They `importorskip`
so they skip cleanly in a build where the selection layer is not present.
"""
from __future__ import annotations

import pytest

select = pytest.importorskip(
    "repo_audit.synthesis.select",
    reason="optional module repo_audit.synthesis.select not importable — feature not present in this build, or the install is incomplete",
)


def test_candidates_excluded_from_topn(finding_factory, record_factory):
    # corroborated|confirmed are eligible; candidate is body-only (D-18-07).
    eligible = finding_factory(confidence="corroborated", severity="major")
    candidate = finding_factory(confidence="candidate", severity="major")

    selected = select.select_top_findings(  # pragma: no cover - skipped until W2
        [eligible, candidate], n=5
    )
    refs = {getattr(f, "rule_id", None) for f in selected}
    assert candidate.rule_id not in refs or candidate not in selected


def test_no_pad_under_fill(finding_factory):
    # only 2 eligible findings, ask for 5 → report exactly 2, NEVER padded.
    eligible = [
        finding_factory(confidence="confirmed", rule_id="a"),
        finding_factory(confidence="corroborated", rule_id="b"),
    ]
    selected = select.select_top_findings(eligible, n=5)  # pragma: no cover
    assert len(selected) == 2
