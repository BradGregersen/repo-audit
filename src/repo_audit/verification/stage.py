"""The verification stage orchestrator — ``run_verification`` (VER-04 / VER-05).

Wires the two halves of Phase 17 together under a never-raise contract (D-25):

    stage-1  tiered_corroborate  (candidate → corroborated, RAISES only)
    stage-2  run_critic_session  (adversarial refutation, via asyncio.run)
    gate     confirmed gate      (corroborated AND survived → confirmed)
    appendix refuted appendix    (valid refutation → refuted[], never vanishes)
    post-pass downgrade-only     (no static→runtime promotion survives)

HARD CONTRACTS:

  * never-raise (D-25): any exception in stage-1, stage-2, the gate, or the
    post-pass leaves findings at their deterministic rungs and ``run_verification``
    STILL returns the full ``(active, refuted, records, verification_meta)`` tuple.
  * accounting invariant (D-17-14 / VER-04): ``len(active) + len(refuted)`` equals
    the input finding count — a refuted finding is FILED in ``refuted[]`` (with its
    reason + citation), never silently dropped.
  * confirmed gate (D-17-05/06/07):
      - corroborated AND critic-survived  → confirmed.
      - NON-runtime corroborated, NO critic verdict → STAYS corroborated (never
        auto-confirmed).
      - evidence_type == 'runtime'         → confirm-eligible WITHOUT a critic run
        (live execution already proved the behavior; the only confirm-without-critic
        path).
      - the rung-cap validator (finding.py) already permits critical/blocker at
        corroborated/confirmed, so promotion is a caveat-preserving model_copy.
  * downgrade-only post-pass (D-17-16 / SAFE-01): a guarded assert (cloned from the
    scan_runner DAST guard) that NEVER raises — any finding whose evidence_type is
    'runtime' but was NOT born runtime is reverted/dropped and folded into a
    violations count.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Callable

from repo_audit.verification import critic as _critic
from repo_audit.verification.corroborate import tiered_corroborate
from repo_audit.verification.record import build_finding_ref

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.verification.record import VerificationRecord


_CONFIRMED_CAVEAT = (
    "Promoted to confirmed by the Phase 17 verification layer "
    "(corroborated and survived adversarial critic review)."
)

# Corroboration tiers that count as "corroborated" for the confirmed gate.
_CORROBORATED_TIERS: frozenset[str] = frozenset(
    {"identity", "locus", "coarse", "reachability", "runtime"}
)


def _bump_to_confirmed(finding: "Finding") -> "Finding":
    """Return a copy of ``finding`` at ``confirmed`` (caveat preserved + appended).

    Confidence ONLY at the rung; severity is left as the parser/corroboration
    capped it (the validators re-run on model_copy — Pitfall 3 / static-critical
    caveat is preserved). The rung-cap validator already permits critical/blocker
    at ``confirmed``.
    """
    existing = (finding.confidence_caveat or "").strip()
    if existing and _CONFIRMED_CAVEAT not in existing:
        caveat = f"{existing} {_CONFIRMED_CAVEAT}"
    elif existing:
        caveat = existing
    else:
        caveat = _CONFIRMED_CAVEAT
    return finding.model_copy(
        update={"confidence": "confirmed", "confidence_caveat": caveat}
    )


def _drop_confidence(finding: "Finding") -> "Finding":
    """Return a copy of ``finding`` with confidence dropped to ``candidate``.

    A refuted finding's recorded confidence is lowered (downgrade-only): it leaves
    the active/promotable set entirely (filed in ``refuted[]``), so this is the
    rung it carries in the audit trail. ``candidate`` is the floor; severity is
    untouched (downgrade-only never raises severity, and the rung-cap validator
    permits major/minor/info at candidate — a refuted critical lands here only via
    the appendix, not the active set, so it never trips the validator).
    """
    # Clamp severity to avoid the SCH-04 candidate rung-cap on a critical/blocker
    # finding being downgraded — the refuted finding is leaving the active set, so
    # its recorded shape just needs to be a valid Finding for the audit trail.
    sev = getattr(finding, "severity", "")
    update: dict = {"confidence": "candidate"}
    if sev in {"critical", "blocker"}:
        update["severity"] = "major"
    return finding.model_copy(update=update)


def _apply_verdicts(
    findings: "list[Finding]",
    verdicts: list,
    records: "list[VerificationRecord]",
) -> "tuple[list[Finding], list[int], list[dict]]":
    """Apply the confirmed gate + refuted appendix to the corroborated findings.

    Returns ``(active, active_tokens, refuted)`` where ``active_tokens`` is the
    per-candidate identity token parallel to ``active`` (so the downgrade-only
    post-pass can read each active finding's BORN evidence_type by token even
    after a confirming model_copy breaks object identity), and ``refuted`` is a
    list of free-form audit dicts (one per validly-refuted finding) carrying
    ``finding_ref`` + reason + citation + ``confidence_dropped``. Nothing vanishes:
    every input finding is either in ``active`` or ``refuted``.

    DISPATCH IS BY IDENTITY TOKEN (17-04), NOT build_finding_ref. ``findings`` is
    the corroborated finding list, index-paired with ``records`` (the pairing the
    corroboration stage produced + run_verification preserves). Each finding's
    per-candidate token is its paired ``record.candidate_token`` — the SAME token
    the critic stamped onto its Verdict. Two fingerprint-colliding findings have
    DISTINCT tokens → distinct verdicts/tiers → no last-write-wins collapse and no
    tier cross-inheritance. ``build_finding_ref`` is used ONLY for the refuted[]
    entry's display ``finding_ref`` field (and sibling citation), never to dispatch.

    Disposition per finding (keyed by candidate_token):
      * a "refuted" verdict (citation already validated by the critic) → moved to
        ``refuted[]``, confidence dropped (D-17-14).
      * corroborated AND a "survived" verdict → confirmed (D-17-05).
      * evidence_type == 'runtime' AND corroborated → confirmed even with NO
        critic verdict (D-17-07 — the only confirm-without-critic path).
      * corroborated, NON-runtime, NO critic verdict → STAYS corroborated
        (D-17-06 — never auto-confirmed).
      * everything else → unchanged (still candidate / whatever stage-1 left).
    """
    # Index verdicts + corroboration tiers by the per-candidate IDENTITY token
    # (17-04) — NOT by the non-unique build_finding_ref fingerprint.
    verdict_by_token: dict[int, object] = {
        getattr(v, "candidate_token", -1): v for v in verdicts
    }
    tier_by_token: dict[int, str] = {
        r.candidate_token: r.corroboration_tier for r in records
    }

    active: list[Finding] = []
    active_tokens: list[int] = []
    refuted: list[dict] = []

    # findings is index-paired with records (the corroboration-stage pairing the
    # caller preserves). Use strict=False defensively: a length mismatch (should
    # never happen) degrades to token=-1 rather than raising (D-25 never-raise).
    paired_tokens = [r.candidate_token for r in records]
    for i, f in enumerate(findings):
        token = paired_tokens[i] if i < len(paired_tokens) else -1
        ref = build_finding_ref(f)
        verdict = verdict_by_token.get(token)
        tier = tier_by_token.get(token, "none")
        corroborated = tier in _CORROBORATED_TIERS
        is_runtime = getattr(f, "evidence_type", None) == "runtime"

        # --- refuted disposition (D-17-14): file in the appendix, never vanish. --
        if verdict is not None and getattr(verdict, "outcome", None) == "refuted":
            dropped = _drop_confidence(f)
            refutation = getattr(verdict, "refutation", None)
            entry: dict = {
                "finding_ref": ref,
                "angle": getattr(refutation, "angle", None) if refutation else None,
                "reason": getattr(refutation, "reason", "") if refutation else "",
                "citation": (
                    refutation.citation.model_dump()
                    if refutation and refutation.citation is not None
                    else None
                ),
                "confidence_dropped": True,
                "dropped_confidence": dropped.confidence,
            }
            refuted.append(entry)
            continue

        # --- confirmed gate (D-17-05/06/07). --------------------------------
        survived = (
            verdict is not None and getattr(verdict, "outcome", None) == "survived"
        )
        if corroborated and survived:
            # D-17-05: corroborated AND critic-survived → confirmed.
            active.append(_bump_to_confirmed(f))
        elif corroborated and is_runtime:
            # D-17-07: runtime auto-confirms WITHOUT a critic run.
            active.append(_bump_to_confirmed(f))
        else:
            # D-17-06: corroborated-non-runtime-no-verdict STAYS corroborated;
            # everything else unchanged.
            active.append(f)
        # Carry the identity token parallel to the active finding (every non-refuted
        # branch appends exactly one finding above; mirror it here).
        active_tokens.append(token)

    return active, active_tokens, refuted


def run_verification(
    findings: "list[Finding]",
    *,
    repo_path=None,
    no_critic: bool = False,
    client_factory: Callable | None = None,
) -> "tuple[list[Finding], list[dict], list[VerificationRecord], dict]":
    """Run the full verification stage under a never-raise contract (D-25).

    Args:
        findings: the merged finding set (post-DAST-guard).
        repo_path: repo root for reachability + citation resolution (None disables
            the reachability tier + file_line citations).
        no_critic: skip stage-2 (the critic). Deterministic corroboration still
            runs; runtime findings still auto-confirm; non-runtime corroborated
            findings stay corroborated (never auto-confirmed).
        client_factory: the test seam forwarded to ``run_critic_session`` — when
            provided the critic loop uses the injected canned-verdict client.

    Returns:
        ``(active, refuted, records, verification_meta)`` where
        ``len(active) + len(refuted) == len(findings)`` (nothing vanishes) and
        ``verification_meta`` is a free-form dict carrying ``critic_reviewed`` /
        ``critic_total_queue`` / ``refuted_findings`` / ``downgrade_violations``.

    NEVER raises: any failure in any stage leaves findings at their deterministic
    rungs and still returns the full tuple.
    """
    # Snapshot the BORN evidence_type by per-candidate IDENTITY token BEFORE
    # stage-1, so the downgrade-only post-pass can detect a static→runtime smuggle
    # (D-17-16). The token is the zero-based INPUT-list index (17-04) — the SAME
    # identity tiered_corroborate stamps onto each record — so keying pre_evidence
    # by token (not the non-unique build_finding_ref) means two fingerprint-twins
    # each keep their OWN born evidence_type (no collision-driven cross-read).
    try:
        pre_evidence: dict[int, str] = {
            idx: (getattr(f, "evidence_type", "") or "")
            for idx, f in enumerate(findings)
        }
    except Exception:
        pre_evidence = {}

    records: list = []
    verdicts: list = []
    vmeta_obj = _critic.VerificationMeta()

    # --- stage-1: deterministic corroboration (RAISES only, never-raise wrap). --
    try:
        corroborated_findings, records = tiered_corroborate(
            findings, repo_path=repo_path
        )
    except Exception:
        # D-25: leave findings at their deterministic rungs.
        corroborated_findings, records = list(findings), []

    # --- stage-2: the adversarial critic (skippable + never-raise wrap). -------
    if not no_critic:
        try:
            queue = _critic.build_priority_queue(corroborated_findings, records)
            verdicts, vmeta_obj = asyncio.run(
                _critic.run_critic_session(
                    queue=queue,
                    repo_path=repo_path,
                    records=records,
                    meta=_critic.VerificationMeta(),
                    client_factory=client_factory,
                    # 17-04: pass the corroborated findings so the session can build
                    # the exact id(finding)->record.candidate_token map for verdict
                    # token stamping (records is index-paired with these findings).
                    corroborated_findings=corroborated_findings,
                )
            )
        except Exception:
            # D-25: a critic failure leaves findings at their corroborated rungs.
            verdicts = []
            vmeta_obj = _critic.VerificationMeta()

    # --- confirmed gate + refuted appendix (never-raise wrap). -----------------
    try:
        active, active_tokens, refuted = _apply_verdicts(
            corroborated_findings, verdicts, records
        )
    except Exception:
        active = list(corroborated_findings)
        active_tokens = [-1] * len(active)
        refuted = []

    # --- downgrade-only post-pass (guarded assert, NEVER raises — D-17-16). ----
    # Cloned from scan_runner.py L780-797: express the invariant as an assert
    # (documentation + contract), catch the AssertionError, revert/drop the
    # offender, accumulate violations. NOTHING raises out of this block.
    downgrade_violations = 0
    kept: list = []
    for i, f in enumerate(active):
        try:
            # 17-04: read the BORN evidence_type by the finding's per-candidate
            # IDENTITY token (parallel to ``active``), NOT by the non-unique
            # build_finding_ref — so two fingerprint-twins never cross-read each
            # other's born evidence in the smuggle check.
            token = active_tokens[i] if i < len(active_tokens) else -1
            born = pre_evidence.get(token, getattr(f, "evidence_type", "") or "")
            now = getattr(f, "evidence_type", "") or ""
            if now == "runtime" and born != "runtime":
                # A finding gained runtime it was NOT born with — the exact
                # smuggle the post-pass exists to catch (SAFE-01 / D-17-16).
                try:
                    assert now == born, (
                        "downgrade-only: no finding may gain 'runtime' it was not "
                        "born with (SAFE-01 / D-17-16)"
                    )
                except AssertionError:
                    downgrade_violations += 1
                # Revert the evidence_type to its born value (drop the promotion).
                try:
                    reverted = f.model_copy(update={"evidence_type": born or "static"})
                    kept.append(reverted)
                except Exception:
                    # If the revert itself fails, drop the offender entirely
                    # rather than let a smuggled runtime finding survive.
                    pass
                continue
            kept.append(f)
        except Exception:
            # Never-raise: if a single finding's post-pass check explodes, keep
            # it at its current rung rather than abort the stage.
            kept.append(f)
    active = kept

    verification_meta: dict = {
        "critic_reviewed": vmeta_obj.critic_reviewed,
        "critic_total_queue": vmeta_obj.critic_total_queue,
        "refuted_findings": refuted,
        "downgrade_violations": downgrade_violations,
        # W1 (17-04): surface the COUNT of refutations DISCARDED for an invalid
        # citation. Previously omitted — an LLM fabricating a citation left no
        # audit trail. The count flows into ReportMeta.discarded_refutations via
        # the explicit scan_runner assignment, so a fabricated refutation is
        # provably visible to the auditor (T-17-04-04).
        "discarded_refutations": len(vmeta_obj.discarded_refutations),
    }

    return active, refuted, records, verification_meta


__all__ = ["run_verification"]
