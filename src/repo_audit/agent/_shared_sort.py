"""The ONE shared ranking primitives — `_SEVERITY_RANK` + the value-derived
tie-break — imported by BOTH `agent.tools._summarize` and `synthesis.rank` so the
render-time and synthesis-time sorts can never drift (D-18 / T-18-02).

`_SEVERITY_RANK` mirrors the `Severity` Literal order in `schema/enums.py`
(blocker=0 … info=4 → lower sorts first / more severe first). `summarize_tie_break`
is the verbatim tail extracted from `_summarize` (agent/tools.py L149-158): a
fully value-derived `(file or "", line or -1, rule_id or "")` triple. Because the
key reads only finding VALUES (never input position), a shuffled input yields the
identical order — the SYN-01 shuffle-stability guarantee.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding

# Severity rank for ranking — lower = more severe → sorts first. Mirrors the
# Severity Literal order in schema/enums.py.
_SEVERITY_RANK: dict[str, int] = {
    "blocker": 0,
    "critical": 1,
    "major": 2,
    "minor": 3,
    "info": 4,
}


def summarize_tie_break(f: "Finding") -> tuple[str, int, str]:
    """The verbatim `_summarize` tie-break tail — `(file or "", line or -1,
    rule_id or "")`. Value-derived (no input-order reliance), so it is
    shuffle-stable. Shared by `_summarize` and `synthesis.rank`."""
    file = getattr(f, "file", None) or ""
    line = getattr(f, "line", None)
    line = line if line is not None else -1
    rule_id = getattr(f, "rule_id", "") or ""
    return (file, line, rule_id)


__all__ = ["_SEVERITY_RANK", "summarize_tie_break"]
