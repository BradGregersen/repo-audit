"""`compute_priority_score` + `score_findings` — Python owns every number (D-69).

The composite is the MULTIPLICATIVE product of four value-derived factors
(severity × confidence × exploitability × blast-radius, D-18-01); a floor on any
axis proportionally suppresses it. EPSS multiplies within band and is NEUTRAL
(multiplier 1.0) when absent (D-18-02 — never a penalty relative to no-EPSS-data).
KEV sets ``band=1`` (the lexicographic top-band, never a numeric boost).

``score_findings`` pairs each finding to its ``VerificationRecord`` by
``candidate_token`` (the zero-based input index) and returns a
``dict[int, PriorityScore]`` keyed on that token — NEVER on the non-unique
``build_finding_ref`` (the 17-04 landmine). Two collision findings therefore keep
DISTINCT scores.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from repo_audit.synthesis.factors import (
    CONFIDENCE_WEIGHT,
    SEVERITY_WEIGHT,
    blast_radius,
    exploitability,
)
from repo_audit.synthesis.record import PriorityScore
from repo_audit.verification.record import build_finding_ref

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.verification.record import VerificationRecord


# Fallback confidence weight floor for an unknown rung (mirrors the factor floor).
_CONFIDENCE_FALLBACK: float = 0.25


def compute_priority_score(
    finding: "Finding",
    record: "VerificationRecord",
    *,
    kev: bool,
    epss: float | None,
) -> PriorityScore:
    """Derive the multiplicative priority for one (finding, record) pair.

    Confidence is read from ``record.final_confidence`` when present (the
    post-verification rung), else ``finding.confidence``. EPSS is raise-only /
    neutral-when-absent (None → multiplier 1.0). KEV → ``band=1``.
    """
    severity_w = SEVERITY_WEIGHT.get(finding.severity, 0.12)

    conf_rung = (getattr(record, "final_confidence", "") or "") or finding.confidence
    confidence_w = CONFIDENCE_WEIGHT.get(conf_rung, _CONFIDENCE_FALLBACK)

    exploitability_w = exploitability(
        finding.evidence_type, getattr(record, "reachable", None), finding.dimension
    )
    blast_radius_w = blast_radius(finding.dimension, finding.file)

    composite = severity_w * confidence_w * exploitability_w * blast_radius_w
    # EPSS: raise-only / neutral-when-absent (D-18-02). Absent EPSS is the neutral
    # baseline (multiplier 1.0). A present EPSS in [0,1] maps to a multiplier of
    # (1.0 + epss) ∈ [1.0, 2.0] — it can ONLY RAISE the composite, NEVER lower it
    # below a finding that has no EPSS data at all. A bare ``composite *= epss``
    # (epss < 1.0) would PENALIZE a finding that HAS data relative to one that does
    # not — exactly the penalty the contract forbids. The value is clamped into
    # [0,1] first so a hostile/garbage network float cannot break the raise-only
    # invariant (WR-05 defense-in-depth, redundant with the epss.py range guard).
    if epss is not None:
        epss_clamped = min(1.0, max(0.0, epss))
        composite *= 1.0 + epss_clamped

    band = 1 if kev else 0

    # dominant_driver = the name of the largest of the four factor contributors.
    drivers = {
        "severity": severity_w,
        "confidence": confidence_w,
        "exploitability": exploitability_w,
        "blast_radius": blast_radius_w,
    }
    dominant_driver = max(drivers, key=lambda k: drivers[k])

    return PriorityScore(
        finding_ref=build_finding_ref(finding),
        candidate_token=getattr(record, "candidate_token", -1),
        severity_w=severity_w,
        confidence_w=confidence_w,
        exploitability_w=exploitability_w,
        blast_radius_w=blast_radius_w,
        composite=composite,
        epss=epss,
        kev=kev,
        band=band,
        dominant_driver=dominant_driver,
    )


def score_findings(
    findings: "list[Finding]",
    records_by_token: "dict[int, VerificationRecord]",
    *,
    tokens: "list[int] | None" = None,
    kev_tokens: frozenset[int] | set[int] = frozenset(),
    epss_by_token: dict[int, float] | None = None,
) -> dict[int, PriorityScore]:
    """Score every finding, keyed on its IDENTITY ``candidate_token`` (NEVER ``finding_ref``).

    ``candidate_token`` is the zero-based index stamped over the ORIGINAL input
    finding list; ``records_by_token`` carries one record per token. ``tokens`` is
    the per-finding identity token list PARALLEL to ``findings`` — pass it whenever
    ``findings`` is a post-verification SUBSET (refuted findings removed), because
    the surviving findings' positions no longer equal their identity tokens. Only
    when ``tokens is None`` (the unfiltered case, e.g. unit tests) does the token
    default to list position. Re-deriving tokens by ``enumerate(findings)`` over a
    refuted-filtered list mispairs every finding after a refutation with the wrong
    record — the exact 17-04 landmine this dispatch identity exists to prevent.

    The returned dispatch map is keyed on the identity token, so two findings
    colliding on ``build_finding_ref`` keep DISTINCT scores (the 17-04 guarantee).
    """
    epss_by_token = epss_by_token or {}
    out: dict[int, PriorityScore] = {}
    pairs = zip(tokens, findings) if tokens is not None else enumerate(findings)
    for token, finding in pairs:
        record = records_by_token.get(token)
        if record is None:
            continue
        out[token] = compute_priority_score(
            finding,
            record,
            kev=token in kev_tokens,
            epss=epss_by_token.get(token),
        )
    return out


__all__ = ["compute_priority_score", "score_findings"]
