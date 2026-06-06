"""Top-N selection — eligibility filter FIRST, then a hard cap, NEVER padded.

The headline "what matters most" band draws ONLY from ELIGIBLE findings
(``corroborated`` | ``confirmed`` — a ``candidate`` is body-only, D-18-07), and it
reports AT MOST ``n`` of them: if fewer than ``n`` are eligible it returns exactly
that many — it NEVER pads back up to ``n`` from the full ranked set (Pitfall 5 /
SAFE-07 / MOD-2 — the CRIT-5 N-of-M no-pad disclosure contract).

The order is: filter to eligible, THEN ``eligible[: min(n, len(eligible))]``. Doing
the slice over the FULL ranked set (``ranked[:n]``) is the bug this module exists to
prevent — that would let a candidate ride into the headline and would pad an
under-filled band.

Two surfaces:
  * :func:`select_top_findings` — finding-only convenience: eligibility read
    straight off ``finding.confidence`` (the renderer/test boundary).
  * :func:`select_top_n` — the stage surface: ``(token, finding)`` pairs +
    ``scores_by_token``; eligibility prefers the POST-verification rung
    (``record``-derived) carried on the score when present, else the finding's own.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.synthesis.record import PriorityScore

# The eligibility gate: only these rungs may enter the headline (D-18-07). A
# ``candidate`` is deliberately excluded — it is body-only until promotion.
_ELIGIBLE_CONFIDENCE: frozenset[str] = frozenset({"corroborated", "confirmed"})


def _is_eligible(confidence: str | None) -> bool:
    """True iff a confidence rung may enter the Top-N headline (D-18-07)."""
    return (confidence or "") in _ELIGIBLE_CONFIDENCE


def select_top_findings(
    findings: "list[Finding]",
    *,
    n: int,
) -> "list[Finding]":
    """Select at most ``n`` ELIGIBLE findings IN ORDER — never padded.

    ``findings`` is assumed already ranked (descending priority). Eligibility is
    read straight off ``finding.confidence``. Returns the eligible prefix capped at
    ``n``; if fewer than ``n`` are eligible, returns exactly that many (no pad).
    """
    eligible = [f for f in findings if _is_eligible(getattr(f, "confidence", None))]
    return eligible[: max(0, n)]


def select_top_n(
    ranked_findings: "list[tuple[int, Finding]]",
    scores_by_token: "dict[int, PriorityScore]",
    n: int,
) -> "list[tuple[int, Finding, PriorityScore | None]]":
    """Select at most ``n`` ELIGIBLE ``(token, finding, score)`` triples — no pad.

    ``ranked_findings`` is the descending-priority ``(token, finding)`` list from
    ``rank_findings``. Eligibility prefers the POST-verification confidence carried
    on the finding (``rank_findings`` operates over the already-rung-stamped active
    set), falling back to ``finding.confidence``. The score is dispatched by token
    (NEVER ``build_finding_ref`` — the 17-04 landmine).

    Filters to eligible FIRST, then ``eligible[: min(n, len(eligible))]`` — fewer
    than ``n`` eligible → exactly that many, never padded from the full set.
    """
    out: list[tuple[int, "Finding", "PriorityScore | None"]] = []
    for token, finding in ranked_findings:
        if not _is_eligible(getattr(finding, "confidence", None)):
            continue
        out.append((token, finding, scores_by_token.get(token)))
    cap = max(0, n)
    return out[:cap]


__all__ = ["select_top_findings", "select_top_n"]
