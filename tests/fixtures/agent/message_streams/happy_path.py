"""Happy-path SDK message stream: 1 tool call + emit_report + result."""
from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock


def build_messages(report_dict: dict) -> list:
    return [
        AssistantMessage(
            content=[ToolUseBlock(id="tu1", name="get_scope_ledger", input={})],
            model="claude-sonnet-4-5",
            usage={"input_tokens": 1000, "output_tokens": 200},
        ),
        AssistantMessage(
            content=[ToolUseBlock(id="tu2", name="emit_report", input=report_dict)],
            model="claude-sonnet-4-5",
            usage={"input_tokens": 1500, "output_tokens": 800},
        ),
        ResultMessage(
            subtype="success", duration_ms=2500, duration_api_ms=2000,
            is_error=False, num_turns=2, session_id="s1",
            total_cost_usd=0.01234,
        ),
    ]
