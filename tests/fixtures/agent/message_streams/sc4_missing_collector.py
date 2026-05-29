"""SC-4: agent emits valid report; findings list is missing one required collector."""
from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock

MESSAGES = [
    AssistantMessage(
        content=[ToolUseBlock(id="tu1", name="emit_report", input={
            "dimensions": [],
            "executive_summary": "",
            "cross_cutting_notes": None,
        })],
        model="claude-sonnet-4-5",
        usage={"input_tokens": 800, "output_tokens": 100},
    ),
    ResultMessage(
        subtype="success", duration_ms=1000, duration_api_ms=900,
        is_error=False, num_turns=1, session_id="s1",
        total_cost_usd=0.00321,
    ),
]
