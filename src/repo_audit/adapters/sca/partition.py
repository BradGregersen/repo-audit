"""Headline vs counted-appendix partition (D-07-04/05, SCA-03/04).

After corroboration, the SCA finding set is split for rendering:

    * HEADLINE — the actionable few. The gate (D-07-04) is BOTH:
        1. a qualifying faithful severity — ``{blocker, critical, major}``
           (this codebase's Severity has NO ``high``; the D-07-04 "{critical,
           high}" band maps to ``{blocker, critical, major}`` per severity.py:
           security-severity 7.0–8.9 -> ``major`` is the "high" tier, and a
           candidate-capped critical/blocker is read from its FAITHFUL severity
           so the cap does not hide it), AND
        2. a fix exists — ``parsed_value['fixed_version'] is not None``.
      A finding actionable today (upgrade-able and serious) is headlined.

    * APPENDIX — everything else, COLLAPSED to a counted, severity-grouped
      summary with the top offending packages NAMED. NEVER deleted (SAFE-01
      no-dilution): ``len(headline) + appendix_total == len(all findings)`` is
      the structural proof. The appendix is "real over volume" — the long tail is
      counted, not silently omitted, and not rendered line-by-line.

Deferred (out of scope this phase):
    * License findings (D-07-08) — partition handles ONLY CVE findings; no
      license Finding is produced here.
    * Registry/staleness crawl (D-07-07) — "outdated" is implicit in the
      ``fixed_version`` already on the finding; there is no separate staleness
      signal and no network crawl.

The result is deterministically ordered (headline + groups + top_packages all
sorted) for SC-5 reproducibility.
"""
from __future__ import annotations

from collections import Counter
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.finding import Finding

# D-07-04 headline severity band — the "{critical, high}" tier mapped to this
# codebase's 5-value Severity taxonomy (NO "high"; major is the 7.0–8.9 tier).
_HEADLINE_SEVERITIES: frozenset[str] = frozenset({"blocker", "critical", "major"})

# How many top offending packages to name per appendix group.
_TOP_PACKAGES_PER_GROUP: int = 5


class AppendixGroup(BaseModel):
    """A counted appendix bucket: one severity tier, its count, top packages."""

    model_config = ConfigDict(extra="forbid")

    severity: str
    count: int
    top_packages: list[str] = Field(default_factory=list)


class ScaPartition(BaseModel):
    """The headline/appendix split of the SCA finding set (D-07-04/05).

    ``len(headline) + appendix_total == len(input findings)`` always holds —
    the appendix is a counted collapse, never a deletion (SAFE-01).
    """

    model_config = ConfigDict(extra="forbid")

    headline: list[Finding] = Field(default_factory=list)
    appendix_groups: list[AppendixGroup] = Field(default_factory=list)
    appendix_total: int = 0


def _faithful_severity(finding: Finding) -> str:
    """Return the pre-cap faithful severity, falling back to the rendered one.

    Phase 6 preserved the faithful severity in ``parsed_value['faithful_severity']``
    before the candidate cap, so a candidate-capped critical still gates on its
    true tier. Falls back to ``finding.severity`` when no faithful value exists.
    """
    faithful = finding.evidence.parsed_value.get("faithful_severity")
    if isinstance(faithful, str) and faithful:
        return faithful
    return finding.severity


def _package_of(finding: Finding) -> Optional[str]:
    """Best-effort package name for appendix grouping (no fabrication).

    Reads ``parsed_value['package']`` (stamped by grype re-extraction / osv
    enrichment fallback). Returns ``None`` when unknown — an unknown package is
    omitted from the top-packages list rather than guessed.
    """
    pkg = finding.evidence.parsed_value.get("package")
    return pkg if isinstance(pkg, str) and pkg else None


def _is_headline(finding: Finding) -> bool:
    """D-07-04 headline gate: qualifying faithful severity AND a fix exists."""
    qualifying_severity = _faithful_severity(finding) in _HEADLINE_SEVERITIES
    has_fix = finding.evidence.parsed_value.get("fixed_version") is not None
    return qualifying_severity and has_fix


def partition(findings: list[Finding]) -> ScaPartition:
    """Split ``findings`` into the headline list and the counted appendix.

    Args:
        findings: the corroborated SCA finding set (CVE findings only — license
            is deferred, D-07-08).

    Returns:
        A :class:`ScaPartition`. ``headline`` holds the actionable findings
        (qualifying severity AND fix); ``appendix_groups`` summarises everything
        else by RENDERED severity with the top offending packages named;
        ``appendix_total`` is the appendix count. The no-deletion invariant
        ``len(headline) + appendix_total == len(findings)`` always holds.
    """
    headline: list[Finding] = []
    appendix: list[Finding] = []
    for finding in findings:
        (headline if _is_headline(finding) else appendix).append(finding)

    # Group the appendix by RENDERED severity; count + name top packages.
    by_severity: dict[str, list[Finding]] = {}
    for finding in appendix:
        by_severity.setdefault(finding.severity, []).append(finding)

    appendix_groups: list[AppendixGroup] = []
    for severity, group in by_severity.items():
        pkg_counts: Counter[str] = Counter(
            pkg for f in group if (pkg := _package_of(f)) is not None
        )
        # Top N by frequency, ties broken alphabetically for determinism (SC-5).
        top = [
            pkg
            for pkg, _ in sorted(
                pkg_counts.items(), key=lambda kv: (-kv[1], kv[0])
            )[:_TOP_PACKAGES_PER_GROUP]
        ]
        appendix_groups.append(
            AppendixGroup(severity=severity, count=len(group), top_packages=top)
        )

    # Deterministic ordering for SC-5: headline + groups sorted by stable keys.
    headline.sort(key=lambda f: (f.rule_id, f.file or "", f.line or 0))
    appendix_groups.sort(key=lambda g: g.severity)

    return ScaPartition(
        headline=headline,
        appendix_groups=appendix_groups,
        appendix_total=len(appendix),
    )


__all__ = ["AppendixGroup", "ScaPartition", "partition"]
