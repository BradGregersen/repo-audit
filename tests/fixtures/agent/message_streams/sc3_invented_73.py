"""SC-3 LOAD-BEARING: agent emits 'Coverage is 73%' invented narrative."""
from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock

INVENTED_REPORT = {
    "dimensions": [{
        "dimension": "test_integrity",
        "narrative": "Coverage is 73% across the suite.",
        "severity_calls": [],
    }],
    "executive_summary": "All findings reviewed.",
    "cross_cutting_notes": None,
}

MESSAGES = [
    AssistantMessage(
        content=[ToolUseBlock(id="tu1", name="emit_report", input=INVENTED_REPORT)],
        model="claude-sonnet-4-5",
        usage={"input_tokens": 1000, "output_tokens": 500},
    ),
    ResultMessage(
        subtype="success", duration_ms=1500, duration_api_ms=1000,
        is_error=False, num_turns=1, session_id="s1",
        total_cost_usd=0.00789,
    ),
]
