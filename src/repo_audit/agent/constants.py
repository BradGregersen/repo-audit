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
    # An estimate only under subscription (OAuth) auth; the SDK signals
    # overage via ResultMessage.subtype == 'error_max_budget_usd' for
    # API-key auth users.
    # Raised 0.50 -> 3.00: the prior $0.50 default cost-capped the agent
    # before per-dimension narration completed on large repos.
    "agent.max_budget_usd": 3.00,
    # --- Phase 17 critic budget knobs (A1 — RESEARCH §"Separate budget knobs") ---
    # The adversarial critic (Plan 17-02) runs as a SECOND, isolated
    # ClaudeSDKClient with its OWN token + wall-clock + turn + usd budget,
    # distinct from the narrator's agent.* knobs above. These are the A1
    # RESEARCH-recommended defaults, pinned per CONTEXT D-17-10 (Claude's
    # discretion). Like the agent.* knobs they are config-overridable via
    # Phase 7's .repo-audit.yaml overlay (which plugs in on top of
    # this dict); the critic budget is sized smaller than the narrator's
    # because each per-candidate review is short (one finding, ~1 tool call,
    # one submit_verdict). max_wall_clock_seconds is the CRIT-5 honest-partial
    # bound: on exhaustion the priority queue STOPS and meta records N of M.
    "critic.max_tokens_per_scan": 60_000,
    "critic.max_turns": 6,
    "critic.max_budget_usd": 1.50,
    "critic.max_wall_clock_seconds": 180,
}


def get_threshold(key: str) -> Any:
    """D-36 indirection lookup. Raises KeyError on unknown keys."""
    return AGENT_DEFAULTS[key]


# --- UNCAPPED-01 cap-resolution helpers (single source of truth) -------------
# These two helpers are the ONLY place the `--uncapped` sentinel values live.
# AGENT_DEFAULTS is NEVER edited at runtime by the uncapped path; instead these
# helpers resolve a cap value through `get_threshold` (capped path) or to the
# appropriate "no cap" sentinel (uncapped path). Keeping them centralized makes
# the cap-removal plumbing directly unit-testable without the live SDK.


def uncap_internal_threshold(key: str, uncapped: bool) -> float:
    """Resolve a cap consumed by OUR OWN in-loop comparisons.

    Returns ``float("inf")`` when ``uncapped`` (an int running tally is never
    ``>=`` inf, so the loop never self-disconnects), else ``get_threshold(key)``.

    Feeds the internal-loop comparison sites:
      - session.py            `running_tokens >= max_tokens`   (agent.max_tokens_per_scan)
      - critic.py _run_live_candidate   `running >= max_tokens` (critic.max_tokens_per_scan)
      - critic.py run_critic_session    `running_tokens >= max_tokens or ... >= max_wall`
        (critic.max_tokens_per_scan, critic.max_wall_clock_seconds)
    """
    if uncapped:
        return float("inf")
    return get_threshold(key)


def uncap_sdk_budget(key: str, uncapped: bool) -> Any:
    """Resolve a cap passed straight to ``ClaudeAgentOptions``.

    Returns ``None`` when ``uncapped`` (the verified SDK no-cap sentinel for
    both ``max_turns`` and ``max_budget_usd`` in claude-agent-sdk 0.2.87 —
    ``None`` means unlimited), else ``get_threshold(key)``.

    Feeds the two SDK option budgets at each construction site:
      - options.py build_options          (agent.max_turns, agent.max_budget_usd)
      - critic.py build_critic_options    (critic.max_turns, critic.max_budget_usd)
    """
    if uncapped:
        return None
    return get_threshold(key)
