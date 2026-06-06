"""SYN-01 — rank_findings is shuffle-stable and KEV top-bands above all non-KEV.

The sort key is fully value-derived (`-band`, `-composite`, then the shared
`_SEVERITY_RANK` + `summarize_tie_break` tail), so a shuffled input yields the
IDENTICAL order. A KEV finding (band=1) outranks every non-KEV finding (band=0)
regardless of composite (D-18-02 lexicographic top-band).
"""
from __future__ import annotations

import random

from repo_audit.synthesis.score import compute_priority_score
from repo_audit.synthesis.rank import rank_findings


def _score_all(findings, kev_tokens=frozenset(), epss=None):
    """Stamp candidate_token over the input list, score each, return scores_by_token."""
    from tests.synthesis.conftest import make_record

    scores = {}
    for token, f in enumerate(findings):
        rec = make_record(candidate_token=token)
        scores[token] = compute_priority_score(
            f, rec, kev=(token in kev_tokens), epss=epss
        )
    return scores


def test_ranking_is_shuffle_stable(finding_factory):
    sevs = ["blocker", "critical", "major", "minor", "info"]
    dims = ["security", "correctness", "quality", "process"]
    findings = [
        finding_factory(
            severity=sevs[i % 5],
            dimension=dims[i % 4],
            rule_id=f"rule_{i % 7}",
            file=f"src/f{i}.ts",
            line=i,
        )
        for i in range(60)
    ]
    # candidate_token is stamped over THIS input order; carry (finding, token) pairs
    # so re-sorting cannot lose the pairing.
    tokened = list(enumerate(findings))
    scores = _score_all(findings)

    first = [tok for tok, _ in rank_findings(tokened, scores)]

    shuffled = tokened[:]
    random.Random(1234).shuffle(shuffled)
    second = [tok for tok, _ in rank_findings(shuffled, scores)]

    assert first == second, "ranking must be permutation-independent (SYN-01)"


def test_kev_outranks_all_non_kev(finding_factory):
    # A KEV finding with a LOW composite (info severity, contained locus).
    kev_finding = finding_factory(
        severity="info", dimension="quality", file="src/tests/x.test.ts",
        rule_id="kev_low", line=1,
    )
    # A non-KEV finding with a HIGH composite (blocker, security, auth path).
    hot_finding = finding_factory(
        severity="blocker", dimension="security", file="src/auth/config.ts",
        rule_id="hot_high", line=2,
    )
    findings = [hot_finding, kev_finding]
    tokened = list(enumerate(findings))
    # token 1 (the kev_finding) is the KEV hit.
    scores = _score_all(findings, kev_tokens={1})

    ranked = rank_findings(tokened, scores)
    top_token = ranked[0][0]

    assert top_token == 1, "a KEV finding must top-band above all non-KEV (D-18-02)"
    assert scores[1].band == 1
    assert scores[0].band == 0
    # …even though the non-KEV finding has the higher composite.
    assert scores[0].composite > scores[1].composite
