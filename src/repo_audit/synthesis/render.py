"""Render the "What matters most" Top-N section (SYN-02, D-18-09).

``render_what_matters_most`` produces the section markdown for a Top-N list. It
is the SAME logic the ``state_report.md.j2`` template inlines (after §1 Executive
summary, before §2 Scope ledger), exposed standalone so the section can be unit
tested without a full ScanReport.

Each item renders: rank, the finding id (``finding_ref``) + ``file:line``, a
severity + confidence rung badge, the deterministic ``composite`` with the named
``dominant_driver``, then — when present — the agent's ``why_it_matters`` prose.
Under ``--no-agent`` (empty ``why_it_matters``) the item renders WITHOUT prose
and never crashes on the missing field (the degrade branch). The section is
empty when ``top_findings`` is empty — NEVER padded (T-18-11).

The renderer reads ONLY the deterministic Python-authored fields + the prose;
an agent-smuggled rank/score is irrelevant here because the list passed in is
the Python-authored one (T-18-08).
"""
from __future__ import annotations

from typing import Any


def _attr(item: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` off a TopFinding model OR a plain dict (test convenience)."""
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def render_what_matters_most(*, top_findings: "list[Any] | None") -> str:
    """Render the "What matters most" section markdown (empty string if no items).

    ``top_findings`` items may be :class:`TopFinding` models or plain dicts (the
    dict form is the lightweight test surface). Returns "" when the list is empty
    or None so the caller can omit the section entirely (no padding, no empty
    header — T-18-11).
    """
    items = list(top_findings or [])
    if not items:
        return ""

    lines: list[str] = ["## What matters most", ""]
    for item in items:
        rank = _attr(item, "rank", "")
        finding_ref = _attr(item, "finding_ref", "") or ""
        file = _attr(item, "file")
        line = _attr(item, "line")
        severity = _attr(item, "severity", "") or ""
        confidence = _attr(item, "confidence", "") or ""
        composite = _attr(item, "composite")
        dominant_driver = _attr(item, "dominant_driver", "") or ""
        why = _attr(item, "why_it_matters", "") or ""

        locus = file or ""
        if file and line is not None:
            locus = f"{file}:{line}"

        # Header line: rank, the linkable finding id, and the locus.
        header = f"### {rank}. `{finding_ref}`"
        if locus:
            header += f" — `{locus}`"
        lines.append(header)
        lines.append("")

        # Deterministic badge line — severity + confidence rung + score/driver.
        badge_parts: list[str] = []
        if severity:
            badge_parts.append(f"**{severity}**")
        if confidence:
            badge_parts.append(f"confidence: {confidence}")
        if composite is not None:
            score = f"score {float(composite):.2f}"
            if dominant_driver:
                score += f" (driver: {dominant_driver})"
            badge_parts.append(score)
        if badge_parts:
            lines.append(" · ".join(badge_parts))
            lines.append("")

        # The ONLY agent-authored content — rendered only when present (degrade
        # branch: empty why_it_matters → no prose line, never a crash).
        if why.strip():
            lines.append(why.strip())
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = ["render_what_matters_most"]
