"""D-15-07 RUNTIME-EXEMPTION TRAP guard (Plan 15-01, Task 2) — SCAFFOLD.

The shared CRIT-4 tripwire ``adapters/supabase/verify_phrasing.assert_verify_
phrasing`` EXEMPTS ``evidence_type == "runtime"`` from its banned-word
(``enforced`` / ``secure`` / ``protected``) check — that exemption was designed
for the RLS two-account probe. So the shared tripwire will NOT catch a banned
word in a ``runtime``-tagged quality_depth finding (axe + lighthouse emit
``runtime`` findings). The QD mappers MUST therefore SELF-DISCIPLINE.

This test asserts that directly, WITHOUT routing through ``assert_verify_
phrasing`` (which would silently pass any runtime finding). It is written
FAILING-by-design as an importorskip-gated scaffold so it SKIPS cleanly NOW (the
Wave-1 mapper modules are absent) and flips ACTIVE the instant Plans 02/03 land
``axe_json`` / ``lighthouse_json`` (the SKIPPED→ACTIVE-on-landing discipline).

The mapper contract this trap enforces (PATTERNS §Verify-phrasing): every QD
Finding ``recommendation`` CONTAINS the substring "verify" and contains NONE of
``enforced`` / ``secure`` / ``protected`` — INCLUDING the ``runtime``-tagged axe /
lighthouse findings the shared tripwire won't police.
"""
from __future__ import annotations

import re

import pytest

# The banned runtime-certainty vocabulary, mirrored from verify_phrasing._BANNED
# (defined locally here so this module does NOT import the shared tripwire — the
# whole point is to self-enforce WITHOUT routing through the runtime-exempt path).
_BANNED = re.compile(r"\b(enforced|secure|protected)\b", re.IGNORECASE)


def _assert_self_disciplined(recommendation: str) -> None:
    """A QD recommendation must say 'verify' and carry no banned word."""
    assert "verify" in recommendation.lower(), (
        "QD recommendation must contain 'verify' (SAFE-05 verify-phrasing)"
    )
    assert _BANNED.search(recommendation) is None, (
        "QD recommendation must NOT contain enforced/secure/protected "
        "(the runtime-exemption trap: the shared tripwire won't catch this)"
    )


axe_json = pytest.importorskip(
    "repo_audit.adapters.quality_depth.axe_json",
    reason="optional module repo_audit.adapters.quality_depth.axe_json not importable — feature not present in this build, or the install is incomplete",
)
lighthouse_json = pytest.importorskip(
    "repo_audit.adapters.quality_depth.lighthouse_json",
    reason="optional module repo_audit.adapters.quality_depth.lighthouse_json not importable — feature not present in this build, or the install is incomplete",
)


def test_axe_runtime_recommendations_self_enforce_verify_phrasing(load_json) -> None:
    """Every axe violation Finding recommendation self-enforces verify-phrasing."""
    doc = load_json("axe_results.json")
    findings = axe_json.map_axe_violations(doc)  # type: ignore[attr-defined]
    assert findings, "axe fixture has violations → expect findings"
    for finding in findings:
        # These ARE runtime findings; the shared tripwire would exempt them.
        assert finding.evidence_type == "runtime"
        _assert_self_disciplined(finding.recommendation)


def test_lighthouse_runtime_recommendation_self_enforces_verify_phrasing(
    load_json,
) -> None:
    """The aggregate Lighthouse perf Finding recommendation self-enforces phrasing."""
    doc = load_json("lighthouse_lhr.json")
    findings = lighthouse_json.map_lighthouse_lhr(doc)  # type: ignore[attr-defined]
    assert findings, "lighthouse fixture → expect an aggregate perf finding"
    for finding in findings:
        assert finding.evidence_type == "runtime"
        _assert_self_disciplined(finding.recommendation)
