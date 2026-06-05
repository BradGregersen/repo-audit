"""Collision regression — fingerprint dispatch is NOT identity-safe (Phase 17 gap).

``build_finding_ref`` returns a NON-unique fingerprint
(``"{source_tool}::{rule_id}::{file}:{line}"``). Two findings emitted by the SAME
tool at the SAME locus collide on that string (live-observed:
``semgrep::owasp.a03.injection::src/auth.py:10``). The Phase 17 verification stage
used that fingerprint as the PRIMARY DISPATCH KEY for verdict application,
corroboration-tier lookup, and pre-evidence snapshotting — so one finding's
critic verdict (or corroboration tier) was silently applied to BOTH.

RED -> GREEN CONTRACT:
    These tests FAIL against build_finding_ref-keyed dispatch (the Phase 17 gap)
    and PASS after the candidate_token identity-dispatch fix (17-04 Task 2).

The three failed truths these tests pin (17-VERIFICATION.md):
  * test_two_same_ref_findings_only_reviewed_one_refuted — VER-04: only the
    finding the critic reviewed is refuted; its fingerprint-twin stays active.
  * test_same_ref_tiers_not_cross_inherited — VER-02: a finding's corroboration
    tier is the tier IT was individually evaluated for — no twin inheritance.
  * test_verdict_dispatch_is_identity_based — VER-03: two colliding candidates
    produce two independently-dispatched verdicts, neither overwriting the other
    (no verdict_by_ref last-write-wins collapse).
"""
from __future__ import annotations

from repo_audit.verification import critic as _critic
from repo_audit.verification import stage as _stage
from repo_audit.verification.record import build_finding_ref


# A file:line that resolves against fake_repo_with_source so a refuted verdict's
# citation is VALID (lands in refuted[], not discarded).
_VALID_CITATION = {"kind": "file_line", "file": "src/app/auth.py", "line": 1}


def _make_colliding_pair(fake_finding):
    """Two SAST findings whose build_finding_ref strings are byte-identical.

    Same source_tool (semgrep), rule_id (owasp.a03.injection), file, line — only
    a NON-ref field (output_snippet / severity) differs, so build_finding_ref
    collapses them to the same fingerprint while they remain distinct objects.
    """
    f_a = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="finding A: tainted sink at sink_a()",
    )
    f_b = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="finding B: tainted sink at sink_b()",
    )
    return f_a, f_b


def test_two_same_ref_findings_only_reviewed_one_refuted(
    fake_finding, fake_repo_with_source
):
    """Only the reviewed twin is refuted; its fingerprint-twin stays active.

    Two findings with an IDENTICAL build_finding_ref. The critic refutes EXACTLY
    ONE of them (with a valid citation); the other is reviewed and survives.
    Against fingerprint-keyed dispatch the single refuted verdict collapses onto
    both twins (or onto the wrong one), so the active set loses a finding it
    should keep. After the identity-token fix, exactly one is refuted and the
    twin survives at its own rung. RED today.
    """
    repo = fake_repo_with_source
    f_a, f_b = _make_colliding_pair(fake_finding)

    # Precondition: the two findings collide on the fingerprint.
    assert build_finding_ref(f_a) == build_finding_ref(f_b)

    # Refute the FIRST queued candidate, survive the SECOND. The mock consumes
    # one spec per queued candidate IN QUEUE ORDER (not by ref), so this maps to
    # the two colliding candidates independently.
    factory = _mock_per_candidate_factory(
        [
            {
                "outcome": "refuted",
                "angle": "existing_control",
                "citation": _VALID_CITATION,
                "reason": "guarded by an upstream control at auth.py:1",
            },
            {"outcome": "survived"},
        ]
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_a, f_b], repo_path=repo, client_factory=factory
    )

    # Nothing vanishes.
    assert len(active) + len(refuted) == 2
    # EXACTLY ONE finding is refuted — not both (the fingerprint collapse bug
    # refutes/loses both or refutes the wrong count).
    assert len(refuted) == 1
    # EXACTLY ONE finding survives in the active set.
    assert len(active) == 1


def test_same_ref_tiers_not_cross_inherited(fake_finding, fake_repo_with_source):
    """A finding's corroboration tier is its OWN — no fingerprint-twin inheritance.

    Build two same-ref findings where only ONE is corroborated by a peer. The
    un-corroborated twin must NOT be promoted to confirmed on the strength of the
    corroborated twin's tier. Against tier_by_ref keying both twins read the same
    (last-written) tier, so the un-corroborated one is wrongly treated as
    corroborated and confirmed when the critic survives it. RED today.
    """
    repo = fake_repo_with_source
    # f_corr is identity-corroborated by a same-locus peer from a DIFFERENT tool
    # (osv) — distinct ref, so it is a genuine corroborating peer, not a twin.
    f_corr = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="corroborated twin",
    )
    f_peer = fake_finding(
        family="sca", source_tool="osv", file="src/app/auth.py", line=1,
        severity="major", rule_id="owasp.a03.injection",
        output_snippet="cross-tool corroborating peer",
    )
    # f_uncorr collides on the fingerprint with f_corr but is a DISTINCT object;
    # it has no corroborating peer of its own beyond the fingerprint twin.
    f_uncorr = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="UN-corroborated twin",
    )

    assert build_finding_ref(f_corr) == build_finding_ref(f_uncorr)

    # All three survive the critic (no refutation) so disposition is driven purely
    # by the corroboration tier. If tiers cross-inherit, the un-corroborated twin
    # is wrongly confirmed.
    factory = _mock_per_candidate_factory(
        [{"outcome": "survived"}] * 4
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_corr, f_peer, f_uncorr], repo_path=repo, client_factory=factory
    )

    # Nothing vanishes.
    assert len(active) + len(refuted) == 3

    # The un-corroborated twin must NOT have been promoted to 'confirmed' on the
    # strength of its corroborated fingerprint-sibling's tier. At most ONE of the
    # two same-ref SAST twins can legitimately be confirmed (the corroborated
    # one). Against tier_by_ref keying, BOTH share the same tier => both confirmed
    # => count is 2. Identity dispatch keeps them independent => count is 1.
    sast_confirmed = [
        f
        for f in active
        if getattr(f, "source_tool", "") == "semgrep"
        and getattr(f, "confidence", "") == "confirmed"
    ]
    assert len(sast_confirmed) <= 1


def test_verdict_dispatch_is_identity_based(fake_finding, fake_repo_with_source):
    """Two colliding candidates get independent verdicts (no last-write collapse).

    mock_critic_client returns [survived, refuted] in QUEUE ORDER for the two
    same-ref candidates. The surviving candidate must keep its survived
    disposition and the refuted candidate must be the ONLY one refuted. Against
    verdict_by_ref = {v.finding_ref: v} the second verdict overwrites the first
    (same key), so the survived disposition is lost. RED today.
    """
    repo = fake_repo_with_source
    f_a, f_b = _make_colliding_pair(fake_finding)
    assert build_finding_ref(f_a) == build_finding_ref(f_b)

    # First queued candidate SURVIVES; second is REFUTED with a valid citation.
    factory = _mock_per_candidate_factory(
        [
            {"outcome": "survived"},
            {
                "outcome": "refuted",
                "angle": "existing_control",
                "citation": _VALID_CITATION,
                "reason": "second candidate refuted at auth.py:1",
            },
        ]
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_a, f_b], repo_path=repo, client_factory=factory
    )

    assert len(active) + len(refuted) == 2
    # Exactly one survived, exactly one refuted — the verdict_by_ref collapse
    # would either lose the survived verdict or double-apply the refuted one.
    assert len(refuted) == 1
    assert len(active) == 1
    # Two verdicts were produced and dispatched independently (not collapsed to
    # one key). meta surfaces both reviews.
    assert vmeta["critic_reviewed"] == 2


def _mock_per_candidate_factory(specs):
    """One canned submit_verdict spec per queued candidate, consumed in order.

    Mirrors conftest.mock_critic_client but bound by QUEUE ORDER (not ref) so two
    fingerprint-colliding candidates each get their OWN verdict. Invokes the REAL
    submit_verdict.handler so the deterministic citation validator + (post-fix)
    candidate_token stamping run.
    """
    seq = list(specs)
    counter = {"i": 0}

    class _Client:
        def __init__(self):
            self._spec = seq[counter["i"]] if counter["i"] < len(seq) else {}
            counter["i"] += 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def run_once(self):
            await _critic.submit_verdict.handler(
                {
                    "outcome": self._spec.get("outcome", "survived"),
                    "angle": self._spec.get("angle"),
                    "citation": self._spec.get("citation"),
                    "reason": self._spec.get("reason", ""),
                }
            )

    def _factory(*, candidate_ref: str, **_kwargs):
        return _Client()

    return _factory
