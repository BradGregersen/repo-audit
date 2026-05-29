"""D-55: 3+ invalid emit_report calls; repair loop exhausts."""
from claude_agent_sdk import AssistantMessage, ToolUseBlock

_INVALID_PAYLOAD = {"dimensions": "should be a list — triggers ValidationError"}

MESSAGES = [
    AssistantMessage(
        content=[ToolUseBlock(id=f"tu{i}", name="emit_report", input=_INVALID_PAYLOAD)],
        model="claude-sonnet-4-5",
        usage={"input_tokens": 800, "output_tokens": 200},
    )
    for i in range(4)
]
