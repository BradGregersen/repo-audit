"""CR-01 regression — synthesis pairs each surviving finding to its OWN record.

The verification stage files refuted findings in a separate appendix, so the
``active`` finding list it hands to ``run_synthesis`` is a SUBSET of the original
input whenever the critic refutes anything. The ``VerificationRecord``s, however,
stay keyed by their original ``candidate_token`` (the zero-based INPUT index).

If synthesis re-derives tokens by ``enumerate(active)`` (list position), then the
moment a finding is refuted every surviving finding after the refuted index is
paired with the WRONG record — the exact 17-04 cross-pairing the ``candidate_token``
dispatch identity exists to prevent. The whole ``--no-agent`` test suite cannot
observe it because nothing is ever refuted there (active == input).

These tests exercise the refutation case directly: they assert the surviving
findings keep their own identity tokens (and therefore their own records'
reachability/confidence), not their post-refutation list positions.
"""
from __future__ import annotations

from repo_audit.synthesis.score import compute_priority_score, score_findings
from repo_audit.synthesis.stage import run_synthesis

from .conftest import make_finding, make_record


def test_score_findings_pairs_by_supplied_identity_token_not_position():
    # Original input was [A, B, C] with tokens 0,1,2; B (token 1) was refuted, so
    # the active subset is [A, C] whose identity tokens are [0, 2].
    a = make_finding(severity="major", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/a.ts", rule_id="A")
    c = make_finding(severity="major", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/c.ts", rule_id="C")
    active = [a, c]
    active_tokens = [0, 2]

    records_by_token = {
        0: make_record(candidate_token=0, reachable=None, final_confidence="corroborated"),
        1: make_record(candidate_token=1, reachable=True, final_confidence="confirmed"),
        2: make_record(candidate_token=2, reachable=None, final_confidence="corroborated"),
    }

    scores = score_findings(active, records_by_token, tokens=active_tokens)

    # The dispatch map is keyed on IDENTITY tokens {0, 2} — NOT the post-refutation
    # positions {0, 1}. Under the position-based bug the second finding would have
    # been keyed 1 and scored against record 1 (B's record).
    assert set(scores) == {0, 2}
    assert scores[0].candidate_token == 0
    assert scores[2].candidate_token == 2

    # And finding C is scored with record 2 (its own), not record 1's signal.
    expected_c = compute_priority_score(
        c, records_by_token[2], kev=False, epss=None
    )
    assert abs(scores[2].composite - expected_c.composite) < 1e-9


def test_run_synthesis_threads_active_tokens_after_refutation():
    # Same [A, C] survivors with original tokens [0, 2]; full records list carries
    # all three original records keyed by candidate_token.
    a = make_finding(severity="major", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/a.ts", rule_id="A")
    c = make_finding(severity="major", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/c.ts", rule_id="C")
    records = [
        make_record(candidate_token=0, reachable=None, final_confidence="corroborated"),
        make_record(candidate_token=1, reachable=True, final_confidence="confirmed"),
        make_record(candidate_token=2, reachable=None, final_confidence="corroborated"),
    ]

    findings, scores_by_token, _top, meta = run_synthesis(
        [a, c], records, repo_path=None, epss_enabled=False, active_tokens=[0, 2],
    )

    assert meta["degraded"] is False
    assert findings == [a, c]
    # Scores are keyed on the surviving findings' identity tokens, not positions.
    assert set(scores_by_token) == {0, 2}
    assert scores_by_token[2].candidate_token == 2


def test_run_synthesis_positional_fallback_when_no_active_tokens():
    # Unfiltered case (nothing refuted): active_tokens omitted → positional tokens
    # 0..N-1 are correct because active == input.
    a = make_finding(severity="major", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/a.ts", rule_id="A")
    b = make_finding(severity="minor", dimension="security", evidence_type="static",
                     confidence="corroborated", file="src/b.ts", rule_id="B")
    records = [
        make_record(candidate_token=0, final_confidence="corroborated"),
        make_record(candidate_token=1, final_confidence="corroborated"),
    ]

    _findings, scores_by_token, _top, meta = run_synthesis(
        [a, b], records, repo_path=None, epss_enabled=False,
    )

    assert meta["degraded"] is False
    assert set(scores_by_token) == {0, 1}
