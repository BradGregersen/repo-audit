"""CRIT-4 verify-phrasing tripwire tests (Plan 08-01, Task 2).

The shared guard every Wave 1 static/heuristic supabase collector routes its
findings through. Proves the contract:

  * any NON-runtime Finding whose report-visible prose carries an enforcement
    word (the banned set) RAISES VerifyPhrasingViolation;
  * ``evidence_type='runtime'`` is the SOLE exemption (D-08-04 — the exit-1
    two-account runtime test is the only sanctioned source of enforcement
    language);
  * verify-phrasing ("verify enforcement") is ALLOWED — the guard is
    word-boundary + case-insensitive, not a naive substring scan;
  * the report-visible prose surface (recommendation / confidence_caveat /
    evidence.output_snippet) is scanned; an enforcement word buried only in
    ``evidence.parsed_value`` diagnostic blobs is exempt.

NOTE: the Phase 1 ``Finding`` schema has no ``message`` field (the plan's
interface note assumed one). The report-visible prose a collector controls is
``recommendation`` (+ confidence_caveat + output_snippet); these tests drive
the tripwire through ``recommendation``. See SUMMARY Rule-3 deviation.

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


def _static_finding(prose: str, *, parsed_value: dict | None = None) -> Finding:
    """A representative non-runtime (static) supabase lint Finding.

    ``prose`` flows into ``recommendation`` — the report-visible field the
    tripwire scans.
    """
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="splinter", parsed_value=parsed_value or {}),
        evidence_type="static",
        confidence="candidate",
        rule_id="rls_disabled_in_public",
        recommendation=prose,
    )


def _runtime_finding(prose: str) -> Finding:
    """A runtime Finding — the two-account probe path (D-08-04)."""
    return Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="rls-two-account-test"),
        evidence_type="runtime",
        confidence="corroborated",
        rule_id="rls_cross_tenant_leak",
        recommendation=prose,
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


@pytest.mark.parametrize("compound", ["RLS-protected", "rls-protected", "grant-protected"])
def test_table_category_compound_does_not_trip(compound):
    """pgrls names a class of tables, not a verified state of this repo.

    Its SEC014 text — a SECURITY DEFINER function "inherits the owner's reach
    into RLS-protected tables" — used to discard the whole pgrls layer.
    """
    findings = [_static_finding(f"inherits the owner's reach into {compound} tables")]
    assert_verify_phrasing(findings)  # does not raise


def test_plain_protected_claim_still_trips_next_to_a_compound():
    """The compound exemption does not open the bare word."""
    findings = [_static_finding("RLS-protected tables; the profiles table is protected")]
    with pytest.raises(VerifyPhrasingViolation):
        assert_verify_phrasing(findings)


def test_enforcement_word_in_caveat_and_snippet_also_raises():
    """The guard scans confidence_caveat + output_snippet too, not just recommendation."""
    via_caveat = Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(tool="splinter"),
        evidence_type="static",
        confidence="candidate",
        rule_id="rls_enabled_no_policy",
        recommendation="policy present; verify enforcement",
        confidence_caveat="tenant rows are secure across accounts",
    )
    with pytest.raises(VerifyPhrasingViolation):
        assert_verify_phrasing([via_caveat])

    via_snippet = Finding(
        dimension="security",
        severity="major",
        evidence=Evidence(
            tool="splinter",
            output_snippet="catalog shows the table is protected",
        ),
        evidence_type="static",
        confidence="candidate",
        rule_id="security_definer_view",
        recommendation="review the view's security mode",
    )
    with pytest.raises(VerifyPhrasingViolation):
        assert_verify_phrasing([via_snippet])


def test_enforcement_word_only_in_parsed_value_is_exempt():
    """parsed_value diagnostic blobs are NOT scanned — only report prose is.

    The tripwire guards the report-visible surface; a banned word inside a
    diagnostic parsed_value blob (a structured payload, not rendered prose) is
    exempt.
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
    assert exc.rule_id == "rls_disabled_in_public"
    assert exc.matched_word.lower() == "enforced"
    assert "rls_disabled_in_public" in str(exc)


def test_empty_list_does_not_raise():
    """No findings -> no violation."""
    assert_verify_phrasing([])
