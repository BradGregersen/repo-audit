"""Phase 4 agent package — Claude Agent SDK orchestration (AGENT-01..08).

Submodule layout (D-53..D-67):
    schema.py       — AgentScanReport, DimensionNarrative, SeverityCall,
                      FaithfulnessViolation (this file's re-exports)
    options.py      — Plan 04-04: build_options() per D-59
    tools.py        — Plan 04-05: @tool getters per D-57/D-58
    session.py      — Plan 04-06: run_agent_session() per D-53
    prompts/scan_report.md.j2 — Plan 04-04/06: D-56 system prompt
    constants.py    — Plan 04-04: AGENT_DEFAULTS (D-65/D-66)
    cost_estimation.py — Plan 04-04: model → USD/Mtok table (Claude's Discretion)

Importing this package is cheap — it only re-exports the Pydantic types.
The agent loop is lazy-imported by cli.py at scan time so `repo-audit detect`
and `repo-audit --doctor` paths pay zero SDK-import cost.
"""
from repo_audit.agent.options import (
    EMIT_REPORT_TOOL_NAME,
    UNIVERSAL_TOOL_NAMES,
    adapter_tool_names,
    build_options,
)
from repo_audit.agent.schema import (
    AgentScanReport,
    DimensionNarrative,
    FaithfulnessViolation,
    SeverityCall,
)
from repo_audit.agent.tools import (
    ALL_TOOLS,
    available_tools_for_prompt,
    build_mcp_server,
    get_emitted_report,
)

__all__ = [
    "AgentScanReport",
    "DimensionNarrative",
    "SeverityCall",
    "FaithfulnessViolation",
    "build_options",
    "UNIVERSAL_TOOL_NAMES",
    "EMIT_REPORT_TOOL_NAME",
    "adapter_tool_names",
    "ALL_TOOLS",
    "available_tools_for_prompt",
    "build_mcp_server",
    "get_emitted_report",
]
