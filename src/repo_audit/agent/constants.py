"""Agent loop defaults + get_threshold() indirection (D-36, D-65, D-66).

AGENT_DEFAULTS is the source of truth for the two budget knobs:
  - max_tokens_per_scan: 150_000 per D-65. The ENFORCEABLE cap under Max
    OAuth auth; the in-loop tally in Plan 04-06 disconnects when this
    threshold is crossed.
  - max_turns: 20 per D-66. Sized for 1 initial + ~10 tool calls +
    ~2 repair rounds + 1 successful emit_report + safety margin.

get_threshold() mirrors the D-36 indirection pattern Phase 2 already uses
(e.g., file_size_cap collector reads thresholds through a similar function
so Phase 7's .repo-audit.yaml overlay can swap values without
touching code). For Phase 4 v1 this is a flat dict lookup; Phase 7's
user-config layer plugs in on top.

DO NOT silently default on unknown keys. Phase 7's overlay can ADD keys
but typos in CALLER code must surface as KeyError so the planner catches
them in dev, not in a quiet runtime regression.
"""
from __future__ import annotations

from typing import Any

AGENT_DEFAULTS: dict[str, Any] = {
    "agent.max_tokens_per_scan": 150_000,
    "agent.max_turns": 20,
    # Documentation-grade under Max OAuth per D-65; the SDK signals
    # overage via ResultMessage.subtype == 'error_max_budget_usd' for
    # API-key auth users (RESEARCH §"Budget signal detection").
    # Raised 0.50 -> 3.00: the prior $0.50 default cost-capped the agent
    # before per-dimension narration completed on large repos (adapt full
    # narration ~$0.63 documentation-grade under Max OAuth; ~$0 actual
    # under a Max subscription).
    "agent.max_budget_usd": 3.00,
}


def get_threshold(key: str) -> Any:
    """D-36 indirection lookup. Raises KeyError on unknown keys."""
    return AGENT_DEFAULTS[key]
