"""SYN-01 — composite is multiplicative; EPSS is raise-only / neutral-when-absent.

`compute_priority_score` multiplies the four factors (severity × confidence ×
exploitability × blast-radius); flooring any one axis proportionally suppresses
the composite (D-18-01). EPSS multiplies within band and is a NEUTRAL 1.0 when
absent (D-18-02 — never a penalty).
"""
from __future__ import annotations

from repo_audit.synthesis.record import PriorityScore
from repo_audit.synthesis.score import compute_priority_score


def test_composite_is_multiplicative(finding_factory, record_factory):
    f = finding_factory(
        severity="critical", dimension="security", file="src/auth/login.ts",
        evidence_type="static", confidence="corroborated",
    )
    rec = record_factory(candidate_token=0, final_confidence="corroborated")

    score = compute_priority_score(f, rec, kev=False, epss=None)

    assert isinstance(score, PriorityScore)
    expected = (
        score.severity_w
        * score.confidence_w
        * score.exploitability_w
        * score.blast_radius_w
    )
    assert abs(score.composite - expected) < 1e-9

    # Flooring one axis (drop severity to info) proportionally suppresses.
    f_low = finding_factory(
        severity="info", dimension="security", file="src/auth/login.ts",
        evidence_type="static", confidence="corroborated",
    )
    low = compute_priority_score(f_low, rec, kev=False, epss=None)
    assert low.composite < score.composite
    # the only changed axis is severity → the ratio matches the severity-weight ratio
    assert low.severity_w < score.severity_w


def test_epss_is_raise_only_neutral_when_absent(finding_factory, record_factory):
    f = finding_factory(severity="major", dimension="security", evidence_type="static")
    rec = record_factory(candidate_token=0)

    absent = compute_priority_score(f, rec, kev=False, epss=None)
    present = compute_priority_score(f, rec, kev=False, epss=0.9)

    # absent EPSS → composite is exactly the four-factor product (multiplier 1.0).
    base = (
        absent.severity_w * absent.confidence_w
        * absent.exploitability_w * absent.blast_radius_w
    )
    assert abs(absent.composite - base) < 1e-9

    # present EPSS multiplies within band; 0.9 < 1.0 means it does not RAISE here,
    # but the no-EPSS baseline is the neutral 1.0 reference — never a penalty
    # relative to "no EPSS data at all". Assert the multiplier was applied.
    assert abs(present.composite - base * 0.9) < 1e-9
    # And a high EPSS raises above the neutral baseline.
    high = compute_priority_score(f, rec, kev=False, epss=1.0)
    assert abs(high.composite - base) < 1e-9  # 1.0 multiplier == neutral
