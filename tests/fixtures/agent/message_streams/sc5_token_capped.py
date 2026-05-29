"""SC-5: agent burns through token budget BEFORE successful emit_report."""
from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock


def build_messages(budget: int = 150_000) -> list:
    per_msg = (budget // 2) + 1000  # cumulative > budget after msg 2
    return [
        AssistantMessage(
            content=[ToolUseBlock(id="tu1", name="get_tsc_diagnostics", input={})],
            model="claude-sonnet-4-5",
            usage={"input_tokens": per_msg, "output_tokens": 0},
        ),
        AssistantMessage(
            content=[ToolUseBlock(id="tu2", name="get_eslint_lint", input={})],
            model="claude-sonnet-4-5",
            usage={"input_tokens": per_msg, "output_tokens": 0},
        ),
        ResultMessage(
            subtype="error_max_budget_usd", duration_ms=3000,
            duration_api_ms=2500, is_error=True, num_turns=2,
            session_id="s1", total_cost_usd=0.50,
        ),
    ]
