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
    # EPSS: raise-only / neutral-when-absent. None → 1.0 (the neutral baseline,
    # NEVER a penalty relative to having no EPSS data at all — D-18-02).
    composite *= epss if epss is not None else 1.0

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
    kev_tokens: frozenset[int] | set[int] = frozenset(),
    epss_by_token: dict[int, float] | None = None,
) -> dict[int, PriorityScore]:
    """Score every finding, keyed on ``candidate_token`` (NEVER ``finding_ref``).

    ``candidate_token`` is the zero-based index stamped over the INPUT finding
    list; ``records_by_token`` carries one record per token. The returned dispatch
    map is keyed on that token, so two findings colliding on ``build_finding_ref``
    keep DISTINCT scores (the 17-04 guarantee).
    """
    epss_by_token = epss_by_token or {}
    out: dict[int, PriorityScore] = {}
    for token, finding in enumerate(findings):
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
