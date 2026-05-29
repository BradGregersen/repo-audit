"""Build the ClaudeAgentOptions for one scan (D-59).

Bound at agent boot ONCE per scan. After build_options returns, the
options dataclass is immutable for the scan duration — `allowed_tools`
cannot grow mid-scan (deferred per CONTEXT section "Deferred Ideas" ->
"Dynamic allowed_tools extension").

The load-bearing SDK gotcha (RESEARCH section "Pitfall 2"): `tools=[]` AND
`allowed_tools=[...]` are BOTH required for SC-1 ("agent has no Write,
no Bash"). Setting only `allowed_tools` does NOT strip built-in tools —
those remain registered; the allow-list only auto-approves what's listed.
`tools=[]` is the empty-preset that strips built-ins entirely (verified
against examples/tools_option.py).

NEVER include Write/Bash/Read/Edit/WebSearch/WebFetch/NotebookEdit/
TodoWrite in allowed_tools. The agent must reach the codebase ONLY
through the explicit `mcp__arch__*` tools registered by Plan 04-05.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, StrictUndefined

from repo_audit.adapters import get_adapter_registry
from repo_audit.agent.constants import get_threshold

if TYPE_CHECKING:
    from claude_agent_sdk import ClaudeAgentOptions
    from claude_agent_sdk.types import McpServerConfig

    from repo_audit.schema.detection import DetectionResult


# Universal collector tool names (D-57) — one MCP getter per Phase 2
# collector, plus 3 ledger/meta convenience getters. The `mcp__arch__`
# prefix matches the SDK naming convention from
# RESEARCH section "Tool definition and registration":
# `allowed_tools=['mcp__<server>__<tool>']`. Server name is 'arch'
# (Plan 04-05's create_sdk_mcp_server(name='arch', ...)).
UNIVERSAL_TOOL_NAMES: tuple[str, ...] = (
    "mcp__arch__get_git_cadence_findings",
    "mcp__arch__get_loc_inventory_findings",
    "mcp__arch__get_secret_detection_findings",
    "mcp__arch__get_doc_presence_findings",
    "mcp__arch__get_todo_markers_findings",
    "mcp__arch__get_file_size_cap_findings",
    "mcp__arch__get_scope_ledger",
    "mcp__arch__get_meta",
    "mcp__arch__get_findings_by_dimension",
)

# The agent -> renderer boundary tool (D-54). ALWAYS in allowed_tools.
EMIT_REPORT_TOOL_NAME: str = "mcp__arch__emit_report"

# Plan 04-05 / 04-06 reconciliation (CRITICAL — logged in 04-05-SUMMARY).
# adapter_tool_names() derives tool names from adapter.yaml's
# `required_collectors` (e.g. typescript-node yields tsc/eslint/knip/
# coverage_lcov -> get_tsc/get_eslint/get_knip/get_coverage_lcov). Plan
# 04-05 registered the four TS @tool getters under the more descriptive
# interface-block names get_tsc_diagnostics/get_eslint_lint/
# get_knip_dead_code/get_lcov_coverage. If allowed_tools used the
# required_collectors-derived names while the MCP server registered the
# descriptive names, the four TS getters would be REGISTERED-but-not-
# ALLOWED and the agent could never call them at the first live connect.
#
# This map reconciles the two so build_options() stays the single source
# of allowed_tools AND every allowed name matches a registered @tool name.
# When a future stack adapter's required_collectors names already match
# its registered getters, no entry is needed here (the name passes through
# unchanged).
_REGISTERED_TOOL_NAME_BY_COLLECTOR: dict[str, str] = {
    "tsc": "get_tsc_diagnostics",
    "eslint": "get_eslint_lint",
    "knip": "get_knip_dead_code",
    "coverage_lcov": "get_lcov_coverage",
}

# Built-in SDK tool names that must NEVER appear in allowed_tools (AGENT-03
# / SC-1). `tools=[]` strips them structurally; this set powers the
# defense-in-depth assertion in build_options.
_FORBIDDEN_BUILTINS: tuple[str, ...] = (
    "Write",
    "Bash",
    "Read",
    "Edit",
    "WebSearch",
    "WebFetch",
    "NotebookEdit",
    "TodoWrite",
)


def adapter_tool_names(stack: str) -> list[str]:
    """Return the mcp__arch__* tool names for a detected stack's parsers.

    Derived from adapter.yaml's `required_collectors` via the
    @register_adapter registry (Phase 3 D-37 + D-40 carry-forward).

    The registry maps stack name -> the adapter's `run` callable (NOT the
    adapter module). The loaded adapter.yaml is exposed as `ADAPTER_CONFIG`
    on the module that DEFINES `run` (the adapter package __init__), so we
    resolve the module via `sys.modules[run.__module__]`. Falls back to an
    empty list if the stack is unregistered or has no `required_collectors`.
    """
    registry = get_adapter_registry()
    run_fn = registry.get(stack)
    if run_fn is None:
        return []
    adapter_module = sys.modules.get(getattr(run_fn, "__module__", ""))
    if adapter_module is None:
        return []
    # Phase 3 adapters expose ADAPTER_CONFIG (the loaded adapter.yaml);
    # CONFIG is the plan-spec alias for the same object.
    config = getattr(adapter_module, "ADAPTER_CONFIG", None)
    if config is None:
        config = getattr(adapter_module, "CONFIG", None)
    if config is None:
        return []
    required = config.get("required_collectors", []) or []
    names: list[str] = []
    for name in required:
        # Reconcile required_collectors names to the actually-registered
        # @tool getter names (Plan 04-05 / 04-06 coordination item). Falls
        # through to `get_{name}` when no remap is needed.
        registered = _REGISTERED_TOOL_NAME_BY_COLLECTOR.get(name, f"get_{name}")
        names.append(f"mcp__arch__{registered}")
    return names


def _render_system_prompt(
    *,
    repo_name: str,
    detected_stacks: list[str],
    partial: bool,
    available_tools: list[dict],
) -> str:
    """Render the D-56 system-prompt template once at agent boot."""
    env = Environment(
        loader=PackageLoader("repo_audit", "agent/prompts"),
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tpl = env.get_template("scan_report.md.j2")
    return tpl.render(
        repo_name=repo_name,
        detected_stacks=detected_stacks,
        partial=partial,
        available_tools=available_tools,
    )


def build_options(
    *,
    detection: "DetectionResult",
    repo_name: str,
    partial: bool,
    mcp_server: "McpServerConfig",
    available_tools_for_prompt: list[dict],
) -> "ClaudeAgentOptions":
    """D-59 — build ClaudeAgentOptions once per scan.

    Args:
      detection: DetectionResult from the Phase 1 detector.
      repo_name: target repo slug (for the system-prompt template).
      partial: whether scope_ledger.unavailable is non-empty.
      mcp_server: the create_sdk_mcp_server return from Plan 04-05.
      available_tools_for_prompt: list of {name, description} dicts the
          system prompt's Section 8 lists. Plan 04-05 supplies this
          (the docstring-lifted descriptions per D-58).

    Returns: ClaudeAgentOptions with:
      - tools=[]  (strips built-in Write/Bash/Read/etc. per Pitfall 2)
      - allowed_tools=UNIVERSAL + adapter_per_stack + ['emit_report']
      - max_turns=20  (D-66 via get_threshold)
      - max_budget_usd=0.50  (documentation-grade under Max OAuth; D-65)
      - system_prompt=<rendered D-56 template>
      - mcp_servers={'arch': mcp_server}
      - permission_mode='bypassPermissions'  (RESEARCH Assumption A2)
    """
    from claude_agent_sdk import ClaudeAgentOptions

    allowed: list[str] = list(UNIVERSAL_TOOL_NAMES)
    for profile in detection.stacks:
        allowed.extend(adapter_tool_names(profile.stack))
    allowed.append(EMIT_REPORT_TOOL_NAME)

    # Sanity: assert no built-in tool name leaked into allowed_tools.
    # SC-1 is structurally enforced by tools=[]; this is defense in depth.
    for forbidden in _FORBIDDEN_BUILTINS:
        assert forbidden not in allowed, (
            f"AGENT-03 violation: {forbidden!r} appeared in allowed_tools"
        )

    system_prompt = _render_system_prompt(
        repo_name=repo_name,
        detected_stacks=[p.stack for p in detection.stacks],
        partial=partial,
        available_tools=available_tools_for_prompt,
    )

    return ClaudeAgentOptions(
        tools=[],  # RESEARCH Pitfall 2 — strip ALL built-ins
        allowed_tools=allowed,
        mcp_servers={"arch": mcp_server},
        max_turns=get_threshold("agent.max_turns"),
        max_budget_usd=get_threshold("agent.max_budget_usd"),
        system_prompt=system_prompt,
        permission_mode="bypassPermissions",
    )
