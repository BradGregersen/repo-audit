"""`rank_findings` — the value-derived, shuffle-stable priority sort (SYN-01).

The sort key is fully value-derived (reads only finding/score VALUES, never input
position), so a shuffled input yields the IDENTICAL order — the SYN-01 guarantee.
The key prepends the KEV band + composite, then reuses the SHARED ``_SEVERITY_RANK``
+ ``summarize_tie_break`` tail extracted from ``_summarize`` (so the render-time
and synthesis sorts cannot drift, T-18-02):

    (-band, -composite, _SEVERITY_RANK[severity], file or "", line or -1, rule_id)

Ascending sort on this key == descending priority. A KEV finding (band=1) therefore
top-bands above EVERY non-KEV finding (band=0) regardless of composite (D-18-02).

The per-finding score is dispatched by ``candidate_token`` (NEVER
``build_finding_ref`` — the 17-04 landmine), so the (token, finding) pairing
survives the re-sort intact.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from repo_audit.agent._shared_sort import _SEVERITY_RANK, summarize_tie_break

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.synthesis.record import PriorityScore


def rank_findings(
    tokened_findings: "list[tuple[int, Finding]]",
    scores_by_token: "dict[int, PriorityScore]",
) -> "list[tuple[int, Finding]]":
    """Return ``(token, finding)`` pairs sorted by descending priority.

    ``tokened_findings`` carries the ``candidate_token`` stamped over the INPUT
    list so the pairing survives a shuffle; the score is dispatched by that token.
    A finding with no score sinks to the bottom (treated as band/composite 0).
    """

    def key(pair: "tuple[int, Finding]"):
        token, f = pair
        score = scores_by_token.get(token)
        band = score.band if score is not None else 0
        composite = score.composite if score is not None else 0.0
        sev_rank = _SEVERITY_RANK.get(getattr(f, "severity", ""), len(_SEVERITY_RANK))
        return (-band, -composite, sev_rank, *summarize_tie_break(f))

    return sorted(tokened_findings, key=key)


__all__ = ["rank_findings"]
