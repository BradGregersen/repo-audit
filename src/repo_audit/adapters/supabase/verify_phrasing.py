"""CRIT-4 verify-phrasing tripwire (SC-1 / SAFE-01) — the shared guard.

Static and heuristic introspection of a FRESH ephemeral database proves a
repo's *intended* policy shape; it never proves that production actually
applies those policies. So a non-runtime Finding's report-visible prose may
NOT claim runtime certainty. The banned vocabulary lives ONLY in the
``_BANNED`` regex literal below (so a source-grep of this module's prose does
not itself trip the very words it polices — the Phase 3 docstring-discipline
lesson).

Contract:
  * Every Wave 1 supabase collector that emits static/heuristic findings calls
    :func:`assert_verify_phrasing` before returning.
  * ``evidence_type == "runtime"`` is the SOLE exemption (D-08-04): the gated
    two-account probe is the one sanctioned source of enforcement language.
  * This is a HARD post-pass — it RAISES on violation (mirroring the
    absoluteness of CRIT-4), unlike the faithfulness gate which strips.

What is scanned (the report-visible message surface):
  The Phase 1 ``Finding`` schema has no single ``message`` field (the plan's
  interface note was written against an assumed field that does not exist —
  see SUMMARY, Rule-3 deviation). The report-visible prose a collector
  controls is ``recommendation`` + ``confidence_caveat`` + the
  ``evidence.output_snippet`` cell rendered in the findings table. Those three
  ARE scanned. The ``evidence.parsed_value`` diagnostic blob is NOT scanned —
  the plan exempts it explicitly (it is a structured diagnostic payload, not
  report prose).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from repo_audit.schema.finding import Finding

# Word-boundary, case-insensitive. The banned vocabulary appears ONLY here.
# \b boundaries mean "insecurely-typed" does NOT match "secure". "RLS-protected"
# and "grant-protected" name a class of tables (pgrls uses them throughout), not
# a verified state of the scanned repo, so those two compounds are let through.
_BANNED = re.compile(
    r"\b(enforced|secure|(?<!rls-)(?<!grant-)protected)\b", re.IGNORECASE
)

# The single evidence_type permitted to use enforcement language (D-08-04).
_EXEMPT_EVIDENCE_TYPE = "runtime"


class VerifyPhrasingViolation(Exception):
    """A non-runtime Finding's prose claimed runtime certainty (CRIT-4).

    Carries the offending ``rule_id`` and the matched word for triage.
    """

    def __init__(self, rule_id: str, matched_word: str) -> None:
        self.rule_id = rule_id
        self.matched_word = matched_word
        super().__init__(
            f"CRIT-4 verify-phrasing violation: Finding rule_id={rule_id!r} "
            f"is non-{_EXEMPT_EVIDENCE_TYPE} yet its report prose carries the "
            f"runtime-certainty word {matched_word!r}. Static/heuristic "
            f"findings must use verify-phrasing (e.g. 'present; verify ...'); "
            f"only evidence_type={_EXEMPT_EVIDENCE_TYPE!r} may assert it."
        )


def _message_surface(finding: Finding) -> str:
    """Concatenate the report-visible prose fields of a Finding.

    ``recommendation`` + ``confidence_caveat`` + ``evidence.output_snippet``.
    Deliberately EXCLUDES ``evidence.parsed_value`` (a structured diagnostic
    blob, exempt per the plan).
    """
    parts = [
        finding.recommendation or "",
        finding.confidence_caveat or "",
        finding.evidence.output_snippet or "",
    ]
    return "\n".join(parts)


def assert_verify_phrasing(findings: Iterable[Finding]) -> None:
    """Raise on the FIRST non-runtime Finding whose prose overclaims.

    For each Finding whose ``evidence_type`` is not ``"runtime"``, scan its
    report-visible prose (see :func:`_message_surface`) for a banned
    runtime-certainty word. On a match, raise
    :class:`VerifyPhrasingViolation`. Findings with
    ``evidence_type == "runtime"`` are exempt (D-08-04). ``parsed_value`` is
    NOT scanned.

    Args:
        findings: the findings a collector is about to return.

    Raises:
        VerifyPhrasingViolation: first offending non-runtime finding.
    """
    for finding in findings:
        if finding.evidence_type == _EXEMPT_EVIDENCE_TYPE:
            continue
        match = _BANNED.search(_message_surface(finding))
        if match is not None:
            raise VerifyPhrasingViolation(finding.rule_id, match.group(0))


def withhold_overclaiming(
    findings: Iterable[Finding],
) -> tuple[list[Finding], list[str]]:
    """Split findings into those the report may carry and the rule ids withheld.

    The per-finding form of :func:`assert_verify_phrasing`, for a third-party
    tool whose own text uses the banned words descriptively (pgrls: "With RLS
    enforced and no write-side policy ..."). One such finding must not discard
    every other finding the tool produced; the caller discloses the rule ids.
    """
    kept: list[Finding] = []
    withheld: list[str] = []
    for finding in findings:
        if finding.evidence_type != _EXEMPT_EVIDENCE_TYPE and _BANNED.search(
            _message_surface(finding)
        ):
            withheld.append(finding.rule_id or "?")
        else:
            kept.append(finding)
    return kept, withheld
