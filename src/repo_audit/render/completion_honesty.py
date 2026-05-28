"""Completion-honesty chokepoint (D-32 / SAFE-08).

Second pre-write lint layer alongside Phase 1's secret_lint.lint_buffer.
On partial scans, presence of standalone "all" / "every" / "complete"
(case-insensitive word-boundary regex) raises CompletionHonestyViolation
-> hard refuse + non-zero exit + stderr diagnostic (Plan 02-06 wires it).

Mirrors render/secret_lint.py shape exactly so future audits can trace
the same "chokepoint between buffer build and disk write" pattern.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# \b ensures "completed" / "fall" / "covered" / "overall" don't match.
_FORBIDDEN_RE = re.compile(r"\b(all|every|complete)\b", re.IGNORECASE)


@dataclass(frozen=True)
class CompletionHonestyHit:
    line: int
    word: str


class CompletionHonestyViolation(Exception):
    def __init__(self, hits: list[CompletionHonestyHit], buffer_name: str) -> None:
        self.hits = list(hits)
        self.buffer_name = buffer_name
        super().__init__(
            f"completion-honesty violation in {buffer_name}: {len(hits)} hit(s)"
        )


def completion_honesty_lint(buf: str, *, partial: bool, buffer_name: str) -> None:
    """Chokepoint: raise CompletionHonestyViolation if partial=True and any standalone
    forbidden token (all/every/complete) appears in buf.

    No-op when partial=False: full scans may legitimately say "all dimensions populated".
    """
    if not partial:
        return
    hits: list[CompletionHonestyHit] = []
    for lineno, line in enumerate(buf.splitlines(), start=1):
        for m in _FORBIDDEN_RE.finditer(line):
            hits.append(CompletionHonestyHit(line=lineno, word=m.group(0)))
    if hits:
        raise CompletionHonestyViolation(hits, buffer_name)


def format_completion_honesty_diagnostic(
    hits: list[CompletionHonestyHit], buffer_name: str
) -> str:
    out = [
        f"REFUSE: completion-honesty violation in {buffer_name} buffer "
        f"(partial scan) - write aborted."
    ]
    for h in hits:
        out.append(
            f'  {buffer_name}:{h.line} disallowed standalone token: "{h.word}"'
        )
    out.append(
        'Rewrite to qualify scope (e.g., "in-scope dimensions" not '
        '"every dimension") OR mark scan complete only when no collector '
        'returned non-ok.'
    )
    return "\n".join(out)
