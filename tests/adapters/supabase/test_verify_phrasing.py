"""CRIT-4 verify-phrasing tripwire tests (Plan 08-01, Task 2).

The shared guard every Wave 1 static/heuristic supabase collector routes its
findings through. Proves the contract:

  * any NON-runtime Finding whose ``message`` carries an enforcement word
    (the banned set) RAISES VerifyPhrasingViolation;
  * ``evidence_type='runtime'`` is the SOLE exemption (D-08-04 — the exit-1
    two-account runtime test is the only sanctioned source of enforcement
    language);
  * verify-phrasing ("verify enforcement") is ALLOWED — the guard is
    word-boundary + case-insensitive, not a naive substring scan;
  * only the report-visible ``message`` field is scanned; an enforcement word
    buried in ``evidence.parsed_value`` diagnostic blobs is exempt.

Findings are built with the Phase 1 schema. Static cases use
``confidence='candidate'`` + ``severity='major'`` to respect SCH-04 (no
candidate+{critical,blocker}).
"""
from __future__ import annotations

import pytest

from repo_audit.adapters.supabase.verify_phrasing import (
    VerifyPhrasingViolation,
    assert_verify_phrasing,
)
from repo_audit.schema.finding import Evidence, Finding


def _static_finding(message: str, *, parsed_value: dict | None = None) -> Finding:
    """A representative non-runtime (static) supabase lint Finding."""
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="splinter", parsed_value=parsed_value or {}),
        evidence_type="static",
        confidence="candidate",
        rule_id="rls_disabled_in_public",
        message=message,
    )


def _runtime_finding(message: str) -> Finding:
    """A runtime Finding — the two-account probe path (D-08-04)."""
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="rls-two-account-test"),
        evidence_type="runtime",
        confidence="corroborated",
        rule_id="rls_cross_tenant_leak",
        message=message,
    )


def test_static_finding_with_enforcement_word_raises():
    """Non-runtime + enforcement word -> CRIT-4 violation."""
    findings = [_static_finding("RLS enforced cross-tenant")]
    with pytest.raises(VerifyPhrasingViolation):
        assert_verify_phrasing(findings)


def test_verify_phrasing_is_allowed():
    """'verify enforcement' must NOT trip — it's the sanctioned phrasing."""
    findings = [_static_finding("policy present; verify enforcement")]
    assert_verify_phrasing(findings)  # does not raise


def test_runtime_finding_with_enforcement_word_does_not_raise():
    """evidence_type='runtime' is the SOLE exemption (D-08-04)."""
    findings = [
        _runtime_finding("RLS enforced cross-tenant on probed tables")
    ]
    assert_verify_phrasing(findings)  # does not raise


@pytest.mark.parametrize("word", ["enforced", "secure", "protected"])
def test_each_banned_word_case_insensitive(word):
    """The full banned word list, matched case-insensitively."""
    for variant in (word, word.upper(), word.capitalize()):
        findings = [_static_finding(f"tenant data is {variant} here")]
        with pytest.raises(VerifyPhrasingViolation):
            assert_verify_phrasing(findings)


def test_word_boundary_no_false_trip_on_substring():
    """A substring inside a larger token must NOT trip (word-boundary regex).

    'insecurely-typed' contains 'secure' as a substring but not as a whole
    word; the guard must let it through.
    """
    findings = [_static_finding("the column is insecurely-typed in the model")]
    assert_verify_phrasing(findings)  # does not raise


def test_enforcement_word_only_in_parsed_value_is_exempt():
    """parsed_value diagnostic blobs are NOT scanned — only message is.

    The tripwire guards the report-visible surface; a banned word inside a
    diagnostic parsed_value blob (never rendered as prose) is exempt.
    """
    findings = [
        _static_finding(
            "policy present; verify enforcement",
            parsed_value={"raw_detail": "table is enforced at the catalog level"},
        )
    ]
    assert_verify_phrasing(findings)  # does not raise


def test_violation_carries_rule_id_and_matched_word():
    """The exception surfaces which rule + which word for triage."""
    findings = [_static_finding("RLS enforced cross-tenant")]
    with pytest.raises(VerifyPhrasingViolation) as exc_info:
        assert_verify_phrasing(findings)
    exc = exc_info.value
    assert "rls_disabled_in_public" in str(exc)
    assert "enforced" in str(exc).lower()


def test_empty_list_does_not_raise():
    """No findings -> no violation."""
    assert_verify_phrasing([])
