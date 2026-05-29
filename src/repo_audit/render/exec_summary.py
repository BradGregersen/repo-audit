"""D-70 SAFE-07 no-dilution executive summary curation at render time.

Two render-time passes:
  1. build_deterministic_exec_header(findings) returns the
     authoritative count line, computed from the structurally-counted
     Finding store — NEVER from agent prose.
  2. dilution_strip_exec_summary(agent_exec_summary) strips any sentence
     that mentions major/minor/info counts (matched by D-70 regex).
     Returns (clean_text, stripped_sentences).

Plan 04-08 Task 2 pre-pends the deterministic header to the cleaned
agent prose and renders both in the template's Executive Summary section.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from repo_audit.render.faithfulness import split_sentences as _split_sentences

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding

# D-70 dilution regex — matches "N {severity}" mentions in any case.
_DILUTION_REGEX = re.compile(
    r"\b(\d+)\s+(blocker|critical|major|minor|info)s?\b",
    re.IGNORECASE,
)

# Plan 04-07's split_sentences only breaks before an UPPERCASE-initial next
# sentence (D-63 boundary `(?<=[.!?])\s+(?=[A-Z])`). Exec-summary prose
# routinely starts a sentence with a digit ("32 major findings cluster..."),
# so a count-led sentence after a period would NOT split and the whole prose
# would be stripped as one unit. We re-split on a digit-initial boundary too
# so each count sentence is isolated for the dilution strip. We do NOT widen
# the shared faithfulness split_sentences (its faithfulness-gate tests pin the
# uppercase-only boundary); this widening is scoped to the D-70 pass.
_DIGIT_INITIAL_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=\d)")


def split_sentences(prose: str) -> list[str]:
    """D-70 sentence splitter: D-63 boundary + a digit-initial next-sentence break.

    Delegates to Plan 04-07's split_sentences (abbreviation pre-mask +
    uppercase-initial boundary) then secondarily splits any chunk that still
    contains a `". 32 ..."`-style digit-led continuation. Keeps the D-70
    dilution strip sentence-granular without touching the shared helper.
    """
    out: list[str] = []
    for chunk in _split_sentences(prose):
        parts = _DIGIT_INITIAL_BOUNDARY.split(chunk)
        for part in parts:
            if part.strip():
                out.append(part)
    return out

# The severities the agent is allowed to discuss in exec summary (SAFE-07).
_ALLOWED_EXEC_SEVERITIES: frozenset[str] = frozenset({"blocker", "critical"})
_DILUTING_SEVERITIES: frozenset[str] = frozenset({"major", "minor", "info"})


def build_deterministic_exec_header(findings: "list[Finding]") -> str:
    """D-70 authoritative count line.

    Format: ``**{N_blocker} blocker, {N_critical} critical finding(s)** across {N_dimensions} dimension(s).``
    """
    n_blocker = sum(1 for f in findings if getattr(f, "severity", "") == "blocker")
    n_critical = sum(1 for f in findings if getattr(f, "severity", "") == "critical")
    affected_dims = {
        getattr(f, "dimension", "")
        for f in findings
        if getattr(f, "severity", "") in ("blocker", "critical")
    }
    affected_dims.discard("")
    n_dimensions = len(affected_dims)
    return (
        f"**{n_blocker} blocker, {n_critical} critical finding(s)** "
        f"across {n_dimensions} dimension(s)."
    )


def dilution_strip_exec_summary(prose: str) -> tuple[str, list[str]]:
    """D-70 — strip any sentence containing a major/minor/info count.

    Returns ``(clean_prose, stripped_sentences)``. The deterministic header
    is pre-pended SEPARATELY by Plan 04-08 Task 2 — this function only
    cleans agent prose.
    """
    if not prose:
        return prose, []
    sentences = split_sentences(prose)
    kept: list[str] = []
    stripped: list[str] = []
    for sentence in sentences:
        matches = list(_DILUTION_REGEX.finditer(sentence))
        has_dilution = any(
            m.group(2).lower() in _DILUTING_SEVERITIES for m in matches
        )
        if has_dilution:
            stripped.append(sentence)
        else:
            kept.append(sentence)
    return " ".join(kept), stripped


__all__ = [
    "build_deterministic_exec_header",
    "dilution_strip_exec_summary",
]
