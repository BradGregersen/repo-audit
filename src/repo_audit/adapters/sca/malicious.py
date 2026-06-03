"""SUP-01 — malicious-package classification + the D-12-06 confirmed promotion.

``promote_malicious`` is a thin, pure transform over the SARIF Findings that
``collect_osv`` ALREADY produces. It partitions out the ``MAL-*`` rule_ids (the
OSV malicious-package advisory feed) and reverses the Phase-6 candidate cap for
those findings ONLY.

WHY THIS IS THE SCOPED D-12-06 EXCEPTION (read 06-CONTEXT D-06-02/03 alongside):
    The generic ``sarif_to_findings`` parser hard-caps EVERY emitted finding to
    ``confidence='candidate'`` and demotes ``critical``/``blocker`` to ``major``
    (SCH-04 forbids candidate + {critical, blocker}). The standing binding
    contract is "Phase 17 corroboration is the ONLY path that promotes
    confidence and restores the faithful severity."

    D-12-06 is a DELIBERATE, SCOPED exception to that rule, and ONLY for the
    OSV malicious-package feed: a ``MAL-*`` advisory is an authoritative
    third-party confirmation that the package IS malicious (analogous to a CVE
    being real, and to Phase 8's runtime two-account LEAK which landed
    ``confirmed``/non-candidate). The OSV malicious feed IS the corroborating
    authority here — distinct from Phase 17's corroboration promotion path.

    CVE/GHSA findings stay candidate-capped (their promotion remains Phase 17's
    job). This module touches MAL-* findings ONLY.

PROMOTION (per MAL-* finding):
    * ``confidence`` candidate -> ``confirmed`` (valid under SCH-04 —
      confirmed + critical/blocker is permitted).
    * ``severity`` restored from the pre-cap faithful severity stashed in
      ``evidence.parsed_value['faithful_severity']`` (restores critical/blocker
      that the parser demoted to major).
    * ``source_collector='malicious_package'`` so MAL findings are visually and
      semantically distinct from CVE findings (D-12-05 intent, T-12-03-SPOOF).
    * a NON-EMPTY ``confidence_caveat`` whenever the promoted severity is
      ``critical`` and ``evidence_type='static'`` (SAFE-01). ``evidence_type``
      stays ``static`` — honest: a MAL-* hit is a feed lookup, NOT a runtime
      observation (D-12-06).

The promoted Finding is CONSTRUCTED FRESH (``Finding(**dict)``) so the SCH-04 /
SAFE-01 / SAFE-03 ``@model_validator``s ACTUALLY run — ``model_copy(update=...)``
does NOT re-run model validators, and we refuse to smuggle an invalid Finding
past them. A missing caveat on a critical+static promotion therefore RAISES at
build time rather than slipping through (T-12-03-EOP mitigation).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from repo_audit.schema.finding import Evidence, Finding

# The OSV malicious-package advisory id prefix. Bare ``MAL-YYYY-NNNN`` ids
# (Assumption A7) so a prefix match is sufficient and precise.
_MAL_PREFIX: str = "MAL-"

# The collector tag that distinguishes a promoted malicious finding from the
# ordinary CVE/GHSA SCA findings (D-12-05 / T-12-03-SPOOF).
_MAL_SOURCE_COLLECTOR: str = "malicious_package"

# The SAFE-01 authority note attached on a promoted critical+static finding when
# the parser left no caveat breadcrumb to reuse. States the authority (the OSV
# malicious-package advisory feed) and is honest that this is a static feed
# lookup, not a runtime observation.
_MAL_AUTHORITY_CAVEAT: str = (
    "Confirmed by the OSV malicious-package advisory feed (MAL-* authoritative "
    "third-party confirmation); evidence_type=static feed lookup, not runtime."
)


@dataclass
class MaliciousPartition:
    """The MAL-* promotion result.

    Returned by :func:`promote_malicious`. It is BOTH:
      * a named-attribute carrier — ``findings`` (the promoted MAL findings) and
        ``cve_findings`` (the MAL-free remainder), and
      * a 2-tuple under unpacking — ``mal, cve = promote_malicious(...)`` works
        because ``__iter__`` yields ``(findings, cve_findings)`` in that order.

    This satisfies both the plan's ``(promoted, remaining)`` tuple contract and
    the Wave-0 test's ``.findings`` / ``.cve_findings`` attribute access from one
    object — no fork.
    """

    findings: list[Finding] = field(default_factory=list)
    cve_findings: list[Finding] = field(default_factory=list)

    def __iter__(self) -> Iterator[list[Finding]]:
        yield self.findings
        yield self.cve_findings


def _faithful_severity(finding: Finding) -> str:
    """Return the pre-cap faithful severity, falling back to the rendered one.

    Copied verbatim from ``partition._faithful_severity``: Phase 6 stashed the
    faithful severity in ``parsed_value['faithful_severity']`` BEFORE the
    candidate cap, so a candidate-capped ``critical`` (rendered as ``major``)
    can be restored to its true tier here. Falls back to ``finding.severity``
    when no faithful value exists.
    """
    faithful = finding.evidence.parsed_value.get("faithful_severity")
    if isinstance(faithful, str) and faithful:
        return faithful
    return finding.severity


def _promote_one(finding: Finding) -> Finding:
    """Build a fresh confirmed + faithful-severity copy of a MAL-* finding.

    Constructs a brand-new ``Finding`` (NOT ``model_copy``) so the SCH-04 /
    SAFE-01 / SAFE-03 validators run on the promoted object. A critical+static
    promotion without a caveat raises here, by design.
    """
    faithful = _faithful_severity(finding)

    # SAFE-01 fires on the LITERAL 'critical' + 'static' (blocker does NOT
    # trigger it). Reuse any caveat breadcrumb the parser already attached (the
    # candidate-cap note), else fall back to the fixed authority note so a
    # critical+static promotion never lacks a caveat.
    caveat: str | None = finding.confidence_caveat
    if faithful == "critical" and finding.evidence_type == "static":
        if not (caveat and caveat.strip()):
            caveat = _MAL_AUTHORITY_CAVEAT

    # Rebuild evidence fresh (Evidence is a pydantic model; reuse its data).
    evidence = Evidence(
        tool=finding.evidence.tool,
        output_snippet=finding.evidence.output_snippet,
        parsed_value=dict(finding.evidence.parsed_value),
        line_range=finding.evidence.line_range,
    )

    return Finding(
        dimension=finding.dimension,
        severity=faithful,  # type: ignore[arg-type]  # validated by Finding
        file=finding.file,
        line=finding.line,
        evidence=evidence,
        evidence_type=finding.evidence_type,  # stays 'static' — honest (D-12-06)
        confidence="confirmed",  # D-12-06 authoritative-feed promotion
        recommendation=finding.recommendation,
        source_tool=finding.source_tool,
        source_collector=_MAL_SOURCE_COLLECTOR,
        rule_id=finding.rule_id,
        confidence_caveat=caveat,
    )


def promote_malicious(osv_findings: list[Finding]) -> MaliciousPartition:
    """Partition MAL-* findings out of the osv set and promote them.

    Args:
        osv_findings: the SARIF Findings ``collect_osv`` produced (MAL-* +
            CVE/GHSA, all candidate-capped by the parser).

    Returns:
        A :class:`MaliciousPartition` carrying ``(promoted_mal_findings,
        remaining_cve_findings)``. It unpacks as a 2-tuple
        (``mal, cve = promote_malicious(...)``) AND exposes ``.findings`` /
        ``.cve_findings``.

        * ``findings`` — each ``MAL-*`` finding rebuilt as
          ``confidence='confirmed'`` with its faithful critical/blocker severity
          restored, ``source_collector='malicious_package'``, and a SAFE-01
          caveat on critical+static.
        * ``cve_findings`` — every non-MAL finding, UNCHANGED and still
          candidate-capped. This list is MAL-free, so ``partition()`` over it
          never double-counts a malicious advisory (T-12-03-SPOOF).
    """
    promoted: list[Finding] = []
    remaining: list[Finding] = []
    for finding in osv_findings:
        if (finding.rule_id or "").startswith(_MAL_PREFIX):
            promoted.append(_promote_one(finding))
        else:
            remaining.append(finding)
    return MaliciousPartition(findings=promoted, cve_findings=remaining)


__all__ = ["MaliciousPartition", "promote_malicious"]
