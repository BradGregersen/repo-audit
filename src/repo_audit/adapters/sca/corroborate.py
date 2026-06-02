"""Two-source corroboration union (SCA-02 / D-07-06).

``corroborate`` unions osv-scanner findings with grype findings on the SHARED
``(cve, package, version)`` key (the ONE keying function ``enrichment_key_for``,
NOT a fork). The rule is deliberately asymmetric between count and confidence:

    * COUNT is conserved. The output has exactly ONE finding per distinct key
      across both inputs — agreement NEVER inflates the count (SCA-02). This is
      the in-phase down payment on Phase 17's verification spine: two tools
      agreeing is a CONFIDENCE signal, never a volume signal.
    * CONFIDENCE is bumped on agreement. A key present in BOTH tools keeps ONE
      finding (the osv finding — it carries Plan-03 enrichment) and is promoted
      ``candidate`` -> ``corroborated``, with a ``confidence_caveat`` recording
      the two-source agreement.
    * SINGLE-SOURCE findings still appear. A key in only one tool (osv-only OR
      grype-only) stays at ``candidate`` and is NEVER dropped — grype-only
      findings surface too (D-07-10).

SEVERITY is NOT re-raised here. SCH-04 permits ``critical`` at ``corroborated``,
but THIS phase only changes confidence; severity stays exactly as the parser
capped it. Phase 17 corroboration is the sole path that promotes severity back
to critical/blocker (DI-06-01-01 binding contract). The bump rationale is
recorded in ``confidence_caveat`` as the Phase-17 breadcrumb.

The output is sorted deterministically by key so a re-scan of identical inputs
is bit-identical (SC-5 reproducibility, RESEARCH Pitfall 7).
"""
from __future__ import annotations

from repo_audit.adapters.sca.enrich import EnrichmentKey, enrichment_key_for
from repo_audit.schema.finding import Finding

_CORROBORATION_CAVEAT = "Corroborated by grype + osv-scanner (two-source agreement)."


def _bump_to_corroborated(finding: Finding) -> Finding:
    """Return a copy of ``finding`` at ``corroborated`` with the agreement caveat.

    Confidence ONLY — severity is left exactly as the parser capped it (Phase 17
    owns severity promotion). The existing caveat (the parser's candidate-cap
    breadcrumb) is preserved and the two-source note is appended so neither the
    SAFE-01 rationale nor the corroboration rationale is lost.
    """
    existing = (finding.confidence_caveat or "").strip()
    if existing and _CORROBORATION_CAVEAT not in existing:
        caveat = f"{existing} {_CORROBORATION_CAVEAT}"
    elif existing:
        caveat = existing
    else:
        caveat = _CORROBORATION_CAVEAT
    return finding.model_copy(
        update={"confidence": "corroborated", "confidence_caveat": caveat}
    )


def corroborate(
    osv_findings: list[Finding], grype_findings: list[Finding]
) -> list[Finding]:
    """Union osv + grype findings on ``(cve, pkg, version)``; bump on agreement.

    Args:
        osv_findings: findings from ``collect_osv`` (primary — carries Plan-03
            enrichment: direct/transitive + fixed_version).
        grype_findings: findings from ``collect_grype`` (secondary — re-keyed so
            its composite ruleId yields the same key, Pitfall 2).

    Returns:
        One finding per distinct key, deterministically sorted by key:
            * key in BOTH -> the osv finding bumped to ``corroborated``;
            * key in only osv -> the osv finding unchanged (candidate);
            * key in only grype -> the grype finding unchanged (candidate).

        ``len(output) == number of distinct keys`` (the count invariant — no
        inflation, SCA-02). Severity is never re-raised (Phase 17 owns that).
    """
    osv_by_key: dict[EnrichmentKey, Finding] = {}
    for finding in osv_findings:
        osv_by_key.setdefault(enrichment_key_for(finding), finding)

    grype_by_key: dict[EnrichmentKey, Finding] = {}
    for finding in grype_findings:
        grype_by_key.setdefault(enrichment_key_for(finding), finding)

    merged: dict[EnrichmentKey, Finding] = {}

    # osv is primary: it owns every key it carries (enrichment lives there). A
    # key also present in grype is bumped to corroborated.
    for key, osv_finding in osv_by_key.items():
        if key in grype_by_key:
            merged[key] = _bump_to_corroborated(osv_finding)
        else:
            merged[key] = osv_finding

    # grype-only keys survive at candidate (D-07-10 — never dropped).
    for key, grype_finding in grype_by_key.items():
        if key not in merged:
            merged[key] = grype_finding

    # Deterministic order (SC-5): sort by the (cve, pkg, version) key.
    return [merged[key] for key in sorted(merged.keys())]


__all__ = ["corroborate"]
