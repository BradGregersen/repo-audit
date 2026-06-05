"""VER-04 / SC4 — confirmed = corroborated AND critic-survived; no-critic-run
stays corroborated; runtime findings confirm without a critic run.

Plan 17-03 (Wave 3) implements the confirmed gate inside ``run_verification``.
These tests drive the gate's three confirm dispositions (D-17-05/06/07).
"""
from __future__ import annotations

from repo_audit.verification import stage as _stage
from repo_audit.verification.record import (
    Citation,
    RefutationRecord,
    VerificationRecord,
    build_finding_ref,
)


def _survived_factory(*, candidate_ref: str, **_kwargs):
    """A client_factory whose critic always returns 'survived' for the candidate."""
    from repo_audit.verification import critic as _critic

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def run_once(self):
            await _critic.submit_verdict.handler({"outcome": "survived"})

    return _Client()


def test_confirmed_requires_corrob_and_survival(fake_finding, monkeypatch):
    """A finding is confirmed only if already corroborated AND critic-survived.

    Two same-rule findings from two distinct tools corroborate (tier-1 identity);
    a 'survived' critic verdict then promotes the survivor to confirmed.
    """
    f_osv = fake_finding(family="sca", source_tool="osv", file="src/a.py", line=3)
    f_grype = fake_finding(family="sca_grype", source_tool="grype", file="src/a.py", line=3)

    active, refuted, records, vmeta = _stage.run_verification(
        [f_osv, f_grype],
        repo_path=None,
        client_factory=_survived_factory,
    )

    # Nothing vanished.
    assert len(active) + len(refuted) == 2
    assert refuted == []
    # Both were corroborated (tier-1 identity) AND survived → confirmed.
    assert {f.confidence for f in active} == {"confirmed"}


def test_runtime_finding_confirms_without_critic_run(fake_finding):
    """An evidence_type=='runtime' finding is confirm-eligible WITHOUT a critic run.

    D-17-07: live execution already proved the behavior; no critic needed
    (no_critic=True skips the critic entirely).
    """
    f_runtime = fake_finding(
        family="rls",
        source_tool="pgrls",
        evidence_type="runtime",
        file="supabase/policies.sql",
        line=12,
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_runtime],
        repo_path=None,
        no_critic=True,
    )

    assert len(active) == 1
    assert refuted == []
    # Runtime auto-confirms even with no critic run.
    assert active[0].confidence == "confirmed"
    assert active[0].evidence_type == "runtime"


def test_non_runtime_corroborated_no_critic_stays_corroborated(fake_finding):
    """D-17-06: a NON-runtime corroborated finding with NO critic verdict STAYS
    corroborated — it is NEVER auto-promoted to confirmed.

    Two identity-corroborated static findings with no_critic=True must remain at
    'corroborated', not silently confirm.
    """
    f_osv = fake_finding(family="sca", source_tool="osv", file="src/b.py", line=7)
    f_grype = fake_finding(family="sca_grype", source_tool="grype", file="src/b.py", line=7)

    active, refuted, records, vmeta = _stage.run_verification(
        [f_osv, f_grype],
        repo_path=None,
        no_critic=True,
    )

    assert len(active) == 2
    assert refuted == []
    # Corroborated, never auto-confirmed (no critic ran).
    assert {f.confidence for f in active} == {"corroborated"}
    assert "confirmed" not in {f.confidence for f in active}


def test_uncorroborated_survived_is_not_confirmed(fake_finding, monkeypatch):
    """A SURVIVED verdict on an UN-corroborated finding does NOT confirm it.

    Confirm requires BOTH corroborated AND survived (D-17-05). A lone candidate
    that survives the critic stays a candidate (it was never corroborated).
    """
    # A single high-severity finding so it enters the queue, but with NO peer →
    # uncorroborated (tier 'none').
    f_lone = fake_finding(
        family="sast",
        source_tool="semgrep",
        severity="major",
        file="src/lone.py",
        line=2,
    )

    active, refuted, records, vmeta = _stage.run_verification(
        [f_lone],
        repo_path=None,
        client_factory=_survived_factory,
    )

    assert len(active) == 1
    assert refuted == []
    # Survived but uncorroborated → NOT confirmed (stays candidate).
    assert active[0].confidence == "candidate"
