"""Headline/appendix partition tests (D-07-04/05, SCA-03/04).

Findings are constructed directly (small, controlled) so each test isolates one
dimension of the gate: faithful severity, fix presence, no-deletion conservation,
and the severity-grouped + top-package appendix shape. License/staleness are
verified to be ABSENT (deferred, D-07-07/08).
"""
from __future__ import annotations

from typing import Optional

from repo_audit.adapters.sca.partition import (
    AppendixGroup,
    ScaPartition,
    partition,
)
from repo_audit.schema.finding import Evidence, Finding


def _finding(
    *,
    rule_id: str,
    rendered_severity: str = "major",
    faithful_severity: Optional[str] = None,
    fixed_version: Optional[str] = None,
    package: Optional[str] = None,
    confidence: str = "candidate",
    confidence_caveat: Optional[str] = None,
) -> Finding:
    """Build a minimal SCA Finding with the partition-relevant parsed_value keys."""
    parsed: dict = {}
    if faithful_severity is not None:
        parsed["faithful_severity"] = faithful_severity
    if fixed_version is not None:
        parsed["fixed_version"] = fixed_version
    else:
        parsed["fixed_version"] = None
    if package is not None:
        parsed["package"] = package
    # A capped critical needs a caveat (SAFE-01) only when severity==critical;
    # tests use rendered 'major' to stay valid at candidate, recording the
    # faithful tier separately in parsed_value (the Phase-6 cap pattern).
    return Finding(
        dimension="security",
        severity=rendered_severity,  # type: ignore[arg-type]
        file="/requirements.txt",
        line=1,
        evidence=Evidence(tool="osv-scanner", output_snippet="", parsed_value=parsed),
        evidence_type="static",
        confidence=confidence,  # type: ignore[arg-type]
        source_tool="osv-scanner",
        rule_id=rule_id,
        confidence_caveat=confidence_caveat,
    )


def test_qualifying_severity_with_fix_goes_headline():
    """faithful severity in {blocker,critical,major} AND a fix -> HEADLINE."""
    f = _finding(
        rule_id="CVE-1", rendered_severity="major", faithful_severity="critical",
        fixed_version="2.0.0", package="urllib3",
    )
    result = partition([f])
    assert result.headline == [f]
    assert result.appendix_total == 0


def test_qualifying_severity_without_fix_goes_appendix():
    """A serious finding with NO fix is not actionable yet -> APPENDIX."""
    f = _finding(
        rule_id="CVE-2", rendered_severity="major", faithful_severity="critical",
        fixed_version=None, package="urllib3",
    )
    result = partition([f])
    assert result.headline == []
    assert result.appendix_total == 1


def test_low_severity_with_fix_goes_appendix():
    """A minor/info finding -> APPENDIX regardless of a fix being present."""
    f = _finding(
        rule_id="CVE-3", rendered_severity="minor", faithful_severity="minor",
        fixed_version="1.2.3", package="requests",
    )
    result = partition([f])
    assert result.headline == []
    assert result.appendix_total == 1


def test_capped_critical_gates_on_faithful_severity():
    """A candidate-capped critical (rendered major) still headlines on its faithful tier."""
    f = _finding(
        rule_id="CVE-4", rendered_severity="major", faithful_severity="critical",
        fixed_version="3.0.0", package="lodash",
    )
    result = partition([f])
    assert f in result.headline


def test_no_deletion_invariant():
    """SAFE-01: len(headline) + appendix_total == total input (nothing dropped)."""
    findings = [
        _finding(rule_id="CVE-a", faithful_severity="critical", fixed_version="1", package="p1"),
        _finding(rule_id="CVE-b", faithful_severity="critical", fixed_version=None, package="p2"),
        _finding(rule_id="CVE-c", rendered_severity="minor", faithful_severity="minor", fixed_version="2", package="p3"),
        _finding(rule_id="CVE-d", rendered_severity="info", faithful_severity="info", fixed_version=None, package="p4"),
        _finding(rule_id="CVE-e", faithful_severity="major", fixed_version="3", package="p5"),
    ]
    result = partition(findings)
    assert len(result.headline) + result.appendix_total == len(findings)


def test_appendix_grouped_by_severity_with_top_packages():
    """Appendix is grouped by severity, counted, with offending packages named."""
    findings = [
        _finding(rule_id="CVE-1", rendered_severity="minor", faithful_severity="minor", fixed_version="1", package="urllib3"),
        _finding(rule_id="CVE-2", rendered_severity="minor", faithful_severity="minor", fixed_version="1", package="urllib3"),
        _finding(rule_id="CVE-3", rendered_severity="minor", faithful_severity="minor", fixed_version="1", package="requests"),
        _finding(rule_id="CVE-4", rendered_severity="info", faithful_severity="info", fixed_version=None, package="flask"),
    ]
    result = partition(findings)
    assert result.headline == []
    groups = {g.severity: g for g in result.appendix_groups}
    assert groups["minor"].count == 3
    assert "urllib3" in groups["minor"].top_packages
    assert "requests" in groups["minor"].top_packages
    # urllib3 is the top offender (2 occurrences) -> first by frequency.
    assert groups["minor"].top_packages[0] == "urllib3"
    assert groups["info"].count == 1
    assert groups["info"].top_packages == ["flask"]


def test_transitive_no_fix_goes_appendix():
    """A transitive-with-no-fix finding -> APPENDIX (not actionable)."""
    f = _finding(
        rule_id="CVE-t", rendered_severity="major", faithful_severity="major",
        fixed_version=None, package="deep-dep",
    )
    result = partition([f])
    assert result.appendix_total == 1
    assert result.headline == []


def test_no_license_findings_produced():
    """SCA-04: partition produces NO license findings (deferred, D-07-08)."""
    f = _finding(rule_id="CVE-x", faithful_severity="major", fixed_version="1", package="p")
    result = partition([f])
    # Output is the same finding objects in; no synthesized license finding.
    all_out = [*result.headline]
    assert all(getattr(x, "dimension", None) == "security" for x in all_out)


def test_partition_is_deterministic():
    """SC-5: identical inputs -> identical headline order + group order."""
    findings = [
        _finding(rule_id="CVE-z", faithful_severity="major", fixed_version="1", package="z"),
        _finding(rule_id="CVE-a", faithful_severity="major", fixed_version="1", package="a"),
    ]
    a = partition(findings)
    b = partition(findings)
    assert [f.rule_id for f in a.headline] == [f.rule_id for f in b.headline]
    assert [f.rule_id for f in a.headline] == ["CVE-a", "CVE-z"]


def test_partition_returns_pydantic_model():
    """ScaPartition / AppendixGroup are extra='forbid' pydantic models."""
    result = partition([])
    assert isinstance(result, ScaPartition)
    assert result.headline == []
    assert result.appendix_groups == []
    assert result.appendix_total == 0
    grp = AppendixGroup(severity="minor", count=1, top_packages=["x"])
    assert grp.severity == "minor"
