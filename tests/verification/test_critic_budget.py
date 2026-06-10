"""VER-03 / SC3 — critic runs under its OWN token + wall-clock budget; honest
partial on exhaustion (CRIT-5); deterministic priority queue (SC-5); never-raise.

Plan 17-02 Task 3 implements ``run_critic_session`` + ``build_priority_queue``.
The live ClaudeSDKClient is replaced by ``mock_critic_client`` (canned
submit_verdict verdicts) so the loop is exercised without the SDK.
"""
from __future__ import annotations

import asyncio
import random

from repo_audit.verification.critic import (
    VerificationMeta,
    build_priority_queue,
    run_critic_session,
)
from repo_audit.verification.record import VerificationRecord, build_finding_ref


# --- build_priority_queue: deterministic + severity filter ------------------


def _records_for(findings):
    """A trivial corroborated VerificationRecord per finding (locus tier)."""
    return [
        VerificationRecord(finding_ref=build_finding_ref(f), corroboration_tier="locus")
        for f in findings
    ]


def test_priority_queue_is_deterministic_under_shuffle(fake_finding):
    """A shuffled input yields an identical reviewed-order (SC-5 / Pitfall 5)."""
    findings = [
        fake_finding(severity="critical", file="a.py", line=1, rule_id="R1", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="critical", file="b.py", line=2, rule_id="R2", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="major", file="c.py", line=3, rule_id="R3"),
        fake_finding(severity="blocker", file="d.py", line=4, rule_id="R4", confidence="corroborated", confidence_caveat="runtime not verified"),
    ]
    records = _records_for(findings)

    q1 = build_priority_queue(findings, records)
    shuffled = list(findings)
    random.Random(7).shuffle(shuffled)
    shuffled_records = _records_for(shuffled)
    q2 = build_priority_queue(shuffled, shuffled_records)

    assert [build_finding_ref(f) for f in q1] == [build_finding_ref(f) for f in q2]
    # blocker sorts first (severity_rank 0).
    assert q1[0].severity == "blocker"


def test_priority_queue_excludes_low_and_info(fake_finding):
    """Low/info findings that are NOT corroborated never enter the queue (D-17-09)."""
    crit = fake_finding(
        severity="critical", file="a.py", line=1, rule_id="R1",
        confidence="corroborated", confidence_caveat="runtime not verified",
    )
    minor = fake_finding(severity="minor", file="b.py", line=2, rule_id="R2")
    info = fake_finding(severity="info", file="c.py", line=3, rule_id="R3")
    findings = [crit, minor, info]
    # Only the critical is corroborated; minor/info carry a 'none' tier so they
    # are excluded by the corroboration filter.
    records = [
        VerificationRecord(finding_ref=build_finding_ref(crit), corroboration_tier="locus"),
        VerificationRecord(finding_ref=build_finding_ref(minor), corroboration_tier="none"),
        VerificationRecord(finding_ref=build_finding_ref(info), corroboration_tier="none"),
    ]
    q = build_priority_queue(findings, records)
    severities = {f.severity for f in q}
    assert "minor" not in severities
    assert "info" not in severities
    assert "critical" in severities


def test_priority_queue_includes_corroborated_major(fake_finding):
    """A corroborated major finding enters the queue even if not critical."""
    major = fake_finding(severity="major", file="a.py", line=1, rule_id="R1")
    rec = VerificationRecord(
        finding_ref=build_finding_ref(major), corroboration_tier="identity"
    )
    uncorrob = fake_finding(severity="minor", file="b.py", line=2, rule_id="R2")
    rec2 = VerificationRecord(
        finding_ref=build_finding_ref(uncorrob), corroboration_tier="none"
    )
    q = build_priority_queue([major, uncorrob], [rec, rec2])
    refs = {build_finding_ref(f) for f in q}
    assert build_finding_ref(major) in refs
    assert build_finding_ref(uncorrob) not in refs


# --- run_critic_session: honest partial on budget exhaustion ----------------


def test_budget_exhaustion_honest_partial(
    fake_repo_with_source, fake_finding, mock_critic_client, monkeypatch
):
    """On budget exhaustion the critic stops and discloses N-of-M honestly.

    VER-03 / SC3: when the wall-clock budget is crossed the loop STOPS before
    reviewing the next finding; meta.critic_reviewed < meta.critic_total_queue;
    un-reviewed findings produce NO verdict.
    """
    findings = [
        fake_finding(severity="critical", file="a.py", line=1, rule_id="R1", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="critical", file="b.py", line=2, rule_id="R2", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="critical", file="c.py", line=3, rule_id="R3", confidence="corroborated", confidence_caveat="runtime not verified"),
    ]
    records = _records_for(findings)
    queue = build_priority_queue(findings, records)

    # Force an immediate wall-clock exhaustion: tiny budget so the bound trips
    # after the first candidate (the loop checks the bound at the top of each
    # iteration). UNCAPPED-01 routed the cap reads through the
    # uncap_internal_threshold resolution helper, so patch THAT seam (the
    # capped path, uncapped=False, returns the resolved value).
    monkeypatch.setattr(
        "repo_audit.verification.critic.uncap_internal_threshold",
        lambda key, uncapped=False: 0 if key == "critic.max_wall_clock_seconds" else 60_000,
    )
    client = mock_critic_client(
        verdicts=[{"outcome": "survived"} for _ in queue]
    )

    verdicts, meta = asyncio.run(
        run_critic_session(
            queue=queue,
            repo_path=fake_repo_with_source,
            records=records,
            meta=VerificationMeta(),
            client_factory=client,
        )
    )
    assert isinstance(meta, VerificationMeta)
    assert meta.critic_total_queue == 3
    assert meta.critic_reviewed < meta.critic_total_queue
    assert len(verdicts) == meta.critic_reviewed


def test_reviews_full_queue_when_budget_ample(
    fake_repo_with_source, fake_finding, mock_critic_client
):
    """With an ample budget the critic reviews every queued candidate."""
    findings = [
        fake_finding(severity="critical", file="a.py", line=1, rule_id="R1", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="critical", file="b.py", line=2, rule_id="R2", confidence="corroborated", confidence_caveat="runtime not verified"),
    ]
    records = _records_for(findings)
    queue = build_priority_queue(findings, records)
    client = mock_critic_client(verdicts=[{"outcome": "survived"} for _ in queue])

    verdicts, meta = asyncio.run(
        run_critic_session(
            queue=queue,
            repo_path=fake_repo_with_source,
            records=records,
            meta=VerificationMeta(),
            client_factory=client,
        )
    )
    assert meta.critic_reviewed == 2
    assert meta.critic_total_queue == 2
    assert all(v.outcome == "survived" for v in verdicts)


def test_raised_sdk_exception_does_not_abort_loop(
    fake_repo_with_source, fake_finding, mock_critic_client
):
    """A raised SDK exception on one candidate does NOT abort the loop (never-raise)."""
    findings = [
        fake_finding(severity="critical", file="a.py", line=1, rule_id="R1", confidence="corroborated", confidence_caveat="runtime not verified"),
        fake_finding(severity="critical", file="b.py", line=2, rule_id="R2", confidence="corroborated", confidence_caveat="runtime not verified"),
    ]
    records = _records_for(findings)
    queue = build_priority_queue(findings, records)

    # First candidate raises; second submits a survived verdict.
    client = mock_critic_client(
        verdicts=[{"raise": True}, {"outcome": "survived"}]
    )

    verdicts, meta = asyncio.run(
        run_critic_session(
            queue=queue,
            repo_path=fake_repo_with_source,
            records=records,
            meta=VerificationMeta(),
            client_factory=client,
        )
    )
    # The loop ran both candidates; the raised one produced no verdict, the
    # second produced one. run_critic_session returned normally.
    assert meta.critic_reviewed == 2
    assert len(verdicts) == 1
    assert verdicts[0].outcome == "survived"
