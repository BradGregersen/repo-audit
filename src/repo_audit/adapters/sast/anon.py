"""SAST-03 — anon-allowlist drop + boundary redaction + RLS cross-link (Plan 10-02).

The single false-positive this tool exists to prevent: a ``p/secrets`` Semgrep
rule flags the PUBLIC Supabase anon / ``sb_publishable_`` key as a "hardcoded
JWT". That key BELONGS in the client and is NOT a leak — flagging it is noise
that buries the real findings. :func:`drop_anon_key_secrets` removes any finding
matching the anon allowlist (and carrying no service_role-distinct marker), and
instead of flagging the anon key it attaches an "is RLS enforced?" cross-link —
the security question that actually matters once the anon key is in the client
(Phase 8 RLS owns that check).

Reuse discipline (mandatory — one source of truth across MOB-02 / SAST / RLS-04):
the anon allowlist, the service_role markers, and the ``[REDACTED:N]``
value-blind redaction are IMPORTED VERBATIM from
``adapters/supabase/footguns.py`` — never re-declared here (the
``mobile/bundled_secrets`` precedent). This keeps the FP-prevention rule in ONE
place; a change to what counts as "the public anon key" updates every pass at
once.

Boundary redaction (T-10-02-01 / SCH-08 defense-in-depth): a genuine secret can
arrive echoed verbatim in the Semgrep SARIF message → the parsed Finding's
``output_snippet``. Every RETAINED finding's snippet is routed through
``footguns._redact_span`` so no raw secret bytes survive into the Finding (the
schema's structural SCH-08 prohibition is the backstop; this is the boundary).
"""
from __future__ import annotations

from repo_audit.adapters.supabase.footguns import (  # verbatim reuse, NO re-declare
    _ANON_ALLOWLIST,
    _has_non_anon_marker,
    _redact_span,
)
from repo_audit.schema.finding import Finding

# The SAST-03 disposition: instead of flagging the anon key, cross-link to the
# RLS analysis ("is RLS enforced?" — the question that matters once the public
# anon key is in the client). Mirrors footguns/bundled_secrets cross_link shape.
_RLS_CROSS_LINK: list[str] = ["RLS"]


def _is_public_anon_key(text: str) -> bool:
    """True when ``text`` is the PUBLIC anon key and nothing service_role-distinct.

    Matches the anon allowlist (``EXPO_PUBLIC_SUPABASE_ANON_KEY`` /
    ``SUPABASE_ANON_KEY`` / ``sb_publishable_`` / a bare ``ANON_KEY`` /
    ``anonKey``) AND carries NO service_role-distinct marker. A line that mixes
    the public anon key with a genuine ``SERVICE_ROLE`` reference is NOT treated
    as the benign anon key — it keeps the service_role half (mirrors
    ``footguns`` scan logic).
    """
    if not any(p.search(text) for p in _ANON_ALLOWLIST):
        return False
    return not _has_non_anon_marker(text)


def drop_anon_key_secrets(findings: list[Finding]) -> list[Finding]:
    """Drop the public-anon-key FP; keep + redact genuine secrets; cross-link RLS.

    For each finding, the text tested is its ``evidence.output_snippet`` joined
    with its ``file`` (so an allowlist name appearing in either is recognized).
    A finding whose text is the public anon key (allowlist match, no
    service_role-distinct marker) is DROPPED — the public key belongs in the
    client and is not a leak (SAST-03). Every RETAINED (genuine) finding has its
    snippet rewritten through ``footguns._redact_span`` (``[REDACTED:N]`` — no
    raw secret bytes survive, T-10-02-01) and gets ``parsed_value["cross_link"]``
    extended with ``"RLS"`` (the "is RLS enforced?" disposition).

    Args:
        findings: secret-rule findings (e.g. from a ``p/secrets`` SARIF parse).

    Returns:
        The kept + redacted findings, in input order. Mutation of the retained
        findings is in place (snippet redacted, cross_link attached).
    """
    kept: list[Finding] = []
    for finding in findings:
        text = f"{finding.evidence.output_snippet}\n{finding.file or ''}"
        if _is_public_anon_key(text):
            # The PUBLIC anon key — drop it (not a leak), do not emit.
            continue

        # Retained = a genuine secret. Redact the snippet at the boundary so no
        # raw bytes enter the Finding (SCH-08 defense-in-depth).
        finding.evidence.output_snippet = _redact_span(finding.evidence.output_snippet)

        # Attach the RLS cross-link (de-duped if some upstream already set one).
        existing = finding.evidence.parsed_value.get("cross_link")
        if isinstance(existing, list):
            for tag in _RLS_CROSS_LINK:
                if tag not in existing:
                    existing.append(tag)
        else:
            finding.evidence.parsed_value["cross_link"] = list(_RLS_CROSS_LINK)

        kept.append(finding)
    return kept


__all__ = ["drop_anon_key_secrets"]
