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
    a NON-ref field (output_snippet) differs, so build_finding_ref collapses them
    to the same fingerprint while they remain distinct objects.

    Two same-tool findings do NOT corroborate EACH OTHER (corroboration needs a
    cross-source signal), so they would not be QUEUED for critic review on their
    own. A cross-tool peer (osv) at the SAME locus identity-corroborates BOTH
    twins — putting them on the priority queue where the verdict-dispatch
    collision actually manifests. The peer is returned so callers can include it
    in the finding set.
    """
    f_a = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="finding A: tainted sink at sink_a()",
    )
    f_b = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="finding B: tainted sink at sink_b()",
    )
    # Cross-tool corroborating peer (DISTINCT fingerprint) at the same locus +
    # rule_id, so both semgrep twins reach the identity tier and get queued.
    peer = fake_finding(
        family="sca", source_tool="osv", file="src/app/auth.py", line=1,
        severity="major", rule_id="owasp.a03.injection",
        output_snippet="cross-tool corroborating peer",
    )
    return f_a, f_b, peer


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
    f_a, f_b, peer = _make_colliding_pair(fake_finding)

    # Precondition: the two SAST twins collide on the fingerprint.
    assert build_finding_ref(f_a) == build_finding_ref(f_b)

    # Queue order (deterministic): osv-peer, semgrep-A (f_a), semgrep-B (f_b).
    # Refute ONLY semgrep-A; survive the peer and semgrep-B. The mock consumes one
    # spec per queued candidate IN QUEUE ORDER, so each colliding twin gets its
    # OWN verdict independently.
    factory = _mock_per_candidate_factory(
        [
            {"outcome": "survived"},  # osv peer
            {
                "outcome": "refuted",  # semgrep-A (f_a)
                "angle": "existing_control",
                "citation": _VALID_CITATION,
                "reason": "guarded by an upstream control at auth.py:1",
            },
            {"outcome": "survived"},  # semgrep-B (f_b) — twin must SURVIVE
        ]
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_a, f_b, peer], repo_path=repo, client_factory=factory
    )

    # Nothing vanishes.
    assert len(active) + len(refuted) == 3
    # EXACTLY ONE finding is refuted — not both twins (the fingerprint collapse
    # bug refutes/loses the wrong count when the colliding twins share a key).
    assert len(refuted) == 1
    # The OTHER two (the surviving twin + the peer) stay active.
    assert len(active) == 2


def test_same_ref_tiers_not_cross_inherited(fake_finding):
    """A finding's corroboration tier is the tier IT was individually evaluated for.

    Drive ``_apply_verdicts`` directly with two same-ref findings whose paired
    records carry DIFFERENT tiers: one identity-corroborated, one tier 'none'. Both
    findings get a 'survived' verdict (so disposition is driven purely by the
    tier). The corroborated finding -> confirmed; the un-corroborated twin -> NOT
    confirmed (stays candidate). Against ``tier_by_ref = {r.finding_ref: ...}`` the
    two same-ref records collapse to ONE entry (last-write-wins), so the
    un-corroborated twin wrongly reads the corroborated tier and is confirmed too.
    Identity dispatch (``tier_by_token``) keeps them independent. RED today.
    """
    from repo_audit.verification.critic import Verdict
    from repo_audit.verification.record import VerificationRecord

    f_corr = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="corroborated twin",
    )
    f_uncorr = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="UN-corroborated twin",
    )
    ref = build_finding_ref(f_corr)
    assert ref == build_finding_ref(f_uncorr)

    # Records index-paired with [f_corr, f_uncorr]; SAME finding_ref, DIFFERENT
    # tier, DISTINCT identity tokens.
    rec_corr = VerificationRecord(
        finding_ref=ref, candidate_token=0, corroboration_tier="identity"
    )
    rec_uncorr = VerificationRecord(
        finding_ref=ref, candidate_token=1, corroboration_tier="none"
    )

    # Both findings survive the critic (verdict keyed by candidate_token).
    v_corr = Verdict(finding_ref=ref, candidate_token=0, outcome="survived")
    v_uncorr = Verdict(finding_ref=ref, candidate_token=1, outcome="survived")

    active, active_tokens, refuted = _stage._apply_verdicts(
        [f_corr, f_uncorr], [v_corr, v_uncorr], [rec_corr, rec_uncorr]
    )

    assert len(refuted) == 0
    assert len(active) == 2

    # The corroborated twin (token 0) is confirmed; the un-corroborated twin
    # (token 1) is NOT confirmed — its tier did not cross-inherit.
    by_token = dict(zip(active_tokens, active))
    assert by_token[0].confidence == "confirmed"
    assert by_token[1].confidence != "confirmed"


def test_verdict_dispatch_is_identity_based(fake_finding, fake_repo_with_source):
    """Two colliding candidates get independent verdicts (no last-write collapse).

    mock_critic_client returns [survived, refuted] in QUEUE ORDER for the two
    same-ref candidates. The surviving candidate must keep its survived
    disposition and the refuted candidate must be the ONLY one refuted. Against
    verdict_by_ref = {v.finding_ref: v} the second verdict overwrites the first
    (same key), so the survived disposition is lost. RED today.
    """
    repo = fake_repo_with_source
    f_a, f_b, peer = _make_colliding_pair(fake_finding)
    assert build_finding_ref(f_a) == build_finding_ref(f_b)

    # Queue order: osv-peer, semgrep-A (f_a), semgrep-B (f_b). The peer survives;
    # f_a SURVIVES; f_b is REFUTED with a valid citation. Against
    # verdict_by_ref = {v.finding_ref: v} the f_b refuted verdict overwrites the
    # f_a survived verdict (same key), losing the survived disposition.
    factory = _mock_per_candidate_factory(
        [
            {"outcome": "survived"},  # osv peer
            {"outcome": "survived"},  # semgrep-A (f_a) — must KEEP survived
            {
                "outcome": "refuted",  # semgrep-B (f_b)
                "angle": "existing_control",
                "citation": _VALID_CITATION,
                "reason": "second candidate refuted at auth.py:1",
            },
        ]
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_a, f_b, peer], repo_path=repo, client_factory=factory
    )

    assert len(active) + len(refuted) == 3
    # Exactly one refuted — the verdict_by_ref collapse would either lose the
    # survived verdict or double-apply the refuted one across the colliding twins.
    assert len(refuted) == 1
    assert len(active) == 2
    # All three candidates were reviewed and dispatched independently.
    assert vmeta["critic_reviewed"] == 3


def test_discarded_refutations_count_reaches_report_meta(fake_finding):
    """W1 (17-04): the discarded-refutation COUNT flows to ReportMeta, not None.

    A critic refutation whose citation does NOT resolve against the real repo is
    DISCARDED (the finding stands) — previously this left NO audit trail. Drive
    run_verification on a finding set that produces >=1 discarded refutation, then
    thread the resulting verification_meta through the SAME individual ReportMeta
    assignment scan_runner does (meta.discarded_refutations = meta.get(...)). Assert
    the count is non-None and >= 1 — proving citation fabrication is provably visible
    to the auditor (T-17-04-04). A bare grep for the symbol is insufficient.
    """
    import datetime

    from repo_audit.schema.report import ReportMeta

    # Two cross-tool peers at the same locus → both corroborated → both queued.
    f_sast = fake_finding(
        family="sast", file="src/app/auth.py", line=1, severity="major",
        output_snippet="sast finding",
    )
    f_peer = fake_finding(
        family="sca", source_tool="osv", file="src/app/auth.py", line=1,
        severity="major", rule_id="owasp.a03.injection",
        output_snippet="cross-tool peer",
    )

    def _fabricated_factory(*, candidate_ref: str, **_kwargs):
        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def run_once(self):
                # A refutation whose file_line citation cannot resolve (no
                # repo_path / non-existent file) → DISCARDED, not applied.
                await _critic.submit_verdict.handler(
                    {
                        "outcome": "refuted",
                        "angle": "existing_control",
                        "citation": {
                            "kind": "file_line",
                            "file": "does/not/exist.py",
                            "line": 9999,
                        },
                        "reason": "fabricated citation",
                    }
                )

        return _Client()

    active, refuted, records, vmeta = _stage.run_verification(
        [f_sast, f_peer], repo_path=None, client_factory=_fabricated_factory
    )

    # The fabricated refutations were discarded — nothing landed in refuted[].
    assert len(refuted) == 0
    discarded = vmeta.get("discarded_refutations")
    assert discarded is not None and discarded >= 1

    # Thread through the SAME individual assignment scan_runner performs.
    meta = ReportMeta(
        repo_slug="x",
        commit_sha="UNCOMMITTED",
        scan_date=datetime.date.today(),
        tool_version="0",
    )
    meta.discarded_refutations = vmeta.get("discarded_refutations")
    assert meta.discarded_refutations is not None
    assert meta.discarded_refutations >= 1


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
