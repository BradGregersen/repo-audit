"""Token -> USD fallback estimator (D-65, RESEARCH section "Pitfall 8").

ResultMessage.total_cost_usd from the claude-agent-sdk is the AUTHORITATIVE
figure (the SDK calculates it from the actual model the run used). This
module's MODEL_USD_PER_MTOK table is the FALLBACK display only -- used by
Plan 04-08's footer rendering when ``meta.total_cost_usd is None``
(RESEARCH Pitfall 8 -- SDK fails to populate total_cost_usd or picks a
model the table doesn't know).

The table is perishable; update when new Claude models ship. Updates
land in this constant with a changelog comment on the line. Do NOT
pin a single model in code paths -- leave model selection to the SDK
(Claude Code CLI's existing config).
"""
from __future__ import annotations

# USD per million tokens, as published by Anthropic. Update on model launches.
# Format: {model_name_substring: (input_usd_per_mtok, output_usd_per_mtok)}
# Matching uses CONTAINS -- `'claude-sonnet-4-5-20250929'` matches the
# 'claude-sonnet-4' key. List most-specific keys first.
MODEL_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    # Sonnet 4.x (2025-2026 lineage)
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    # Opus 4.x (premium tier)
    "claude-opus-4": (15.00, 75.00),
    # Haiku 4.x (cheaper tier)
    "claude-haiku-4": (0.80, 4.00),
}


def estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> float | None:
    """Compute USD cost from a model name + token usage.

    Returns None when no MODEL_USD_PER_MTOK key matches `model` -- the
    caller falls back to ResultMessage.total_cost_usd (RESEARCH Pitfall 8).
    """
    for key, (input_rate, output_rate) in MODEL_USD_PER_MTOK.items():
        if key in model:
            return (
                (input_tokens / 1_000_000) * input_rate
                + (output_tokens / 1_000_000) * output_rate
            )
    return None
