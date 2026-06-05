"""Plan 17-01 Task 1 — sidecar VerificationRecord / Citation / RefutationRecord
models (extra='forbid') + the build_finding_ref composite fingerprint.

These models live in a SIDECAR keyed by a finding fingerprint so Finding stays
extra='forbid' and SCH-08-untouched (RESEARCH §"Why a sidecar, not Finding
fields"). The Citation.kind 'sibling_ref' variant makes the D-17-13 duplicate
refutation angle structurally citable.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from repo_audit.verification.record import (
    Citation,
    RefutationRecord,
    VerificationRecord,
    build_finding_ref,
)


def test_verification_record_defaults():
    rec = VerificationRecord(finding_ref="osv::CVE-1::a.py:1")
    assert rec.corroboration_tier == "none"
    assert rec.reachable is None
    assert rec.corroborated_by == []
    assert rec.critic_ran is False
    assert rec.refutation is None
    assert rec.discarded_refutations == []
    assert rec.final_confidence == ""


def test_verification_record_forbids_extra_field():
    with pytest.raises(ValidationError):
        VerificationRecord(finding_ref="osv::CVE-1::a.py:1", bogus_field="x")


def test_verification_record_requires_nonempty_finding_ref():
    with pytest.raises(ValidationError):
        VerificationRecord(finding_ref="")


def test_citation_sibling_ref_kind_validates():
    """D-17-13: the duplicate angle is structurally citable via kind='sibling_ref'."""
    c = Citation(kind="sibling_ref", sibling_finding_ref="grype::CVE-1::a.py:1")
    assert c.kind == "sibling_ref"
    assert c.sibling_finding_ref == "grype::CVE-1::a.py:1"


def test_citation_file_line_kind_validates():
    c = Citation(kind="file_line", file="src/a.py", line=10)
    assert c.kind == "file_line"
    assert c.file == "src/a.py"
    assert c.line == 10


def test_citation_rejects_unknown_kind():
    with pytest.raises(ValidationError):
        Citation(kind="totally_made_up")


def test_citation_forbids_extra_field():
    with pytest.raises(ValidationError):
        Citation(kind="file_line", bogus="x")


def test_refutation_record_shape():
    cit = Citation(kind="file_line", file="src/a.py", line=3)
    ref = RefutationRecord(
        angle="upstream_guard",
        citation=cit,
        reason="guarded by an input validator at the boundary",
        citation_valid=True,
    )
    assert ref.angle == "upstream_guard"
    assert ref.citation.kind == "file_line"
    assert ref.citation_valid is True


def test_refutation_record_rejects_unknown_angle():
    cit = Citation(kind="file_line", file="src/a.py", line=3)
    with pytest.raises(ValidationError):
        RefutationRecord(
            angle="not_an_angle", citation=cit, reason="x", citation_valid=False
        )


def test_refutation_record_duplicate_angle_with_sibling_ref():
    """The duplicate angle pairs with a sibling_ref citation end-to-end."""
    cit = Citation(kind="sibling_ref", sibling_finding_ref="grype::CVE-1::a.py:1")
    ref = RefutationRecord(
        angle="duplicate",
        citation=cit,
        reason="same CVE already reported by grype on the same locus",
        citation_valid=True,
    )
    assert ref.angle == "duplicate"
    assert ref.citation.sibling_finding_ref == "grype::CVE-1::a.py:1"


def test_build_finding_ref_composite(fake_finding):
    f = fake_finding(source_tool="osv", rule_id="CVE-2026-0001", file="src/a.py", line=7)
    assert build_finding_ref(f) == "osv::CVE-2026-0001::src/a.py:7"


def test_build_finding_ref_none_fallbacks():
    from repo_audit.schema.finding import Evidence, Finding

    f = Finding(
        dimension="security",
        severity="info",
        file=None,
        line=None,
        evidence=Evidence(tool="x"),
        evidence_type="static",
        confidence="candidate",
        source_tool="",
        rule_id="",
    )
    # Empty-string fallbacks for None file/line and empty tool/rule_id:
    # "{tool}::{rule}::{file}:{line}" → "" :: "" :: "" : "" → five colons.
    assert build_finding_ref(f) == ":::::"
