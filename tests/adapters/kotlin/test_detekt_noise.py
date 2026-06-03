"""D-11-08 — detekt noise floor contract test (Plan 11-01 Wave 0 scaffolding).

SKIPPED until BOTH Wave-1 modules land (``kotlin.detekt`` + ``kotlin.noise``),
then activates automatically. The detekt noise floor (11-RESEARCH Pitfall 7)
keys on the ruleId PREFIX: ``detekt.style.*`` and ``detekt.formatting.*`` are the
pure-style/formatting families that get dropped; ``detekt.potential-bugs.*``
(and the other complexity/exceptions/coroutines/empty-blocks families) are KEPT.

This pins the prefix-keyed behaviour so a maintainer who reworks the floor to key
on message text or path (the Pitfall-7 wrong approach) trips this test.
"""
from __future__ import annotations

import pytest

detekt = pytest.importorskip(
    "repo_audit.adapters.kotlin.detekt",
    reason="Wave 1 (plan 11-02) not yet landed — kotlin.detekt missing",
)
noise = pytest.importorskip(
    "repo_audit.adapters.kotlin.noise",
    reason="Wave 1 (plan 11-02) not yet landed — kotlin.noise missing",
)

from repo_audit.schema.finding import Evidence, Finding  # noqa: E402


def _detekt_finding(rule_id: str) -> Finding:
    """Build a representative detekt Finding at the parser's default shape.

    warning->major, evidence_type='static', confidence='candidate' (the shape
    the generic SARIF parser stamps for detekt per 11-RESEARCH Pitfall 6).
    """
    return Finding(
        dimension="quality",
        severity="major",
        evidence_type="static",
        confidence="candidate",
        source_tool="detekt",
        source_collector="kotlin_adapter",
        rule_id=rule_id,
        evidence=Evidence(tool="detekt", parsed_value={"rule_id": rule_id}),
    )


def test_noise_floor_drops_style_and_formatting():
    """detekt.style.* + detekt.formatting.* dropped; detekt.potential-bugs.* kept."""
    findings = [
        _detekt_finding("detekt.style.MagicNumber"),
        _detekt_finding("detekt.formatting.Indentation"),
        _detekt_finding("detekt.potential-bugs.UnsafeCallOnNullableType"),
    ]

    kept = noise.apply_detekt_noise_floor(findings)

    kept_rule_ids = {f.rule_id for f in kept}
    assert "detekt.potential-bugs.UnsafeCallOnNullableType" in kept_rule_ids
    assert "detekt.style.MagicNumber" not in kept_rule_ids
    assert "detekt.formatting.Indentation" not in kept_rule_ids
