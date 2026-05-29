"""Agent in-process MCP tools (D-54, D-57, D-58).

Phase 4 contract: collectors and adapter parsers have ALREADY run by the
time the agent boots (Plan 04-06's session loop calls them BEFORE
`ClaudeSDKClient.connect()`). The agent's tools are PURE GETTERS over a
module-level `_RESULTS` dict that the session loop populates. There is
NO action-tool semantics in v1 (D-57 lock).

The load-bearing boundary: `emit_report` (D-54) is the agent → renderer
boundary. Its input_schema is `AgentScanReport.model_json_schema()`; the
SDK validates incoming agent calls against that schema BEFORE invoking
the handler. The handler runs `AgentScanReport.model_validate(args)` for
defense in depth (the SDK and Pydantic validate the same model; if the
Pydantic check fails despite passing the SDK gate, the D-55 repair loop
fires by returning `{'is_error': True}`).

`_RESULTS` is module-level state because the @tool decorator wraps async
functions whose signature cannot accept the findings list as a parameter
(the SDK passes `args: dict[str, Any]`). The session loop's `build_mcp_server`
populates `_RESULTS` before connecting; the tools read from it. This is the
standard pattern from RESEARCH §"Pattern 2" verbatim.
"""
from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from repo_audit.agent.schema import AgentScanReport

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger


# Module-level state the session loop populates before connect().
_RESULTS: dict[str, Any] = {
    "findings": [],
    "scope_ledger": None,
    "meta": None,
}

# Set by emit_report on successful validation; consumed by session loop
# to return as the agent's final structured output.
_EMITTED_REPORT: AgentScanReport | None = None


# -- helpers -------------------------------------------------------------

def _module_description(dotted_path: str) -> str:
    """Lift the top-of-module docstring as the @tool description (D-58)."""
    import importlib

    mod = importlib.import_module(dotted_path)
    doc = inspect.getdoc(mod) or ""
    return doc.strip()


def _findings_by_source_tool(source_tool: str) -> list[dict]:
    return [
        f.model_dump(mode="json")
        for f in _RESULTS.get("findings", [])
        if getattr(f, "source_tool", "") == source_tool
    ]


def _findings_by_source_collector(source_collector: str) -> list[dict]:
    return [
        f.model_dump(mode="json")
        for f in _RESULTS.get("findings", [])
        if getattr(f, "source_collector", "") == source_collector
    ]


def _wrap(payload: object) -> dict[str, Any]:
    """Wrap a serializable payload as the SDK's tool-result envelope."""
    return {"content": [{"type": "text", "text": json.dumps(payload, default=str)}]}


# -- universal collector getters ----------------------------------------

@tool(
    "get_git_cadence_findings",
    _module_description("repo_audit.collectors.git_cadence"),
    {"_unused": str},
)
async def get_git_cadence_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("git_cadence"))


@tool(
    "get_loc_inventory_findings",
    _module_description("repo_audit.collectors.loc_inventory"),
    {"_unused": str},
)
async def get_loc_inventory_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("loc_inventory"))


@tool(
    "get_secret_detection_findings",
    _module_description("repo_audit.collectors.secret_detection"),
    {"_unused": str},
)
async def get_secret_detection_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("secret_detection"))


@tool(
    "get_doc_presence_findings",
    _module_description("repo_audit.collectors.doc_presence"),
    {"_unused": str},
)
async def get_doc_presence_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("doc_presence"))


@tool(
    "get_todo_markers_findings",
    _module_description("repo_audit.collectors.todo_markers"),
    {"_unused": str},
)
async def get_todo_markers_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("todo_markers"))


@tool(
    "get_file_size_cap_findings",
    _module_description("repo_audit.collectors.file_size_cap"),
    {"_unused": str},
)
async def get_file_size_cap_findings(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_collector("file_size_cap"))


# -- TypeScript adapter getters -----------------------------------------

@tool(
    "get_tsc_diagnostics",
    _module_description("repo_audit.adapters.typescript.parsers.tsc"),
    {"_unused": str},
)
async def get_tsc_diagnostics(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_tool("tsc"))


@tool(
    "get_eslint_lint",
    _module_description("repo_audit.adapters.typescript.parsers.eslint"),
    {"_unused": str},
)
async def get_eslint_lint(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_tool("eslint"))


@tool(
    "get_knip_dead_code",
    _module_description("repo_audit.adapters.typescript.parsers.knip"),
    {"_unused": str},
)
async def get_knip_dead_code(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_tool("knip"))


@tool(
    "get_lcov_coverage",
    _module_description("repo_audit.adapters.typescript.parsers.lcov"),
    {"_unused": str},
)
async def get_lcov_coverage(args: dict[str, Any]) -> dict[str, Any]:
    return _wrap(_findings_by_source_tool("lcov"))


# -- ledger / meta / dimension aggregator ------------------------------

@tool(
    "get_scope_ledger",
    (
        "Returns the scan's ScopeLedger — scanned directories, skipped "
        "directories with reasons, and unavailable collectors with "
        "reasons. Read this near the start of your loop so you know "
        "what's a real gap vs intentional skip vs unavailable tool."
    ),
    {"_unused": str},
)
async def get_scope_ledger(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _RESULTS.get("scope_ledger")
    if ledger is None:
        return _wrap({"scanned": [], "skipped": [], "unavailable": [], "notes": ""})
    return _wrap(ledger.model_dump(mode="json"))


@tool(
    "get_meta",
    (
        "Returns the scan's ReportMeta — repo slug, commit SHA, scan "
        "date, tool version, detected stacks, partial-scan flag. The "
        "partial flag drives completion-honesty discipline in your "
        "narrative."
    ),
    {"_unused": str},
)
async def get_meta(args: dict[str, Any]) -> dict[str, Any]:
    meta = _RESULTS.get("meta")
    if meta is None:
        return _wrap({})
    return _wrap(meta.model_dump(mode="json"))


@tool(
    "get_findings_by_dimension",
    (
        "Returns ALL Findings in a given dimension regardless of "
        "source_tool. Useful for cross-tool synthesis (e.g., quality "
        "dimension combines eslint, file_size_cap, loc_inventory). "
        "Argument: {'dimension': one of 'security' | 'architecture_rot' "
        "| 'test_integrity' | 'correctness' | 'quality' | 'process' | "
        "'observability'}."
    ),
    {"dimension": str},
)
async def get_findings_by_dimension(args: dict[str, Any]) -> dict[str, Any]:
    dim = args.get("dimension", "")
    out = [
        f.model_dump(mode="json")
        for f in _RESULTS.get("findings", [])
        if getattr(f, "dimension", "") == dim
    ]
    return _wrap(out)


# -- emit_report — the agent → renderer boundary (D-54) -----------------

@tool(
    "emit_report",
    (
        "Emit the final structured scan report. Call this EXACTLY ONCE "
        "after narrating every dimension with findings. The renderer "
        "composes the markdown from your structured payload; you do "
        "NOT write markdown yourself. Schema: AgentScanReport "
        "(dimensions[], executive_summary, cross_cutting_notes). "
        "On schema-validation failure, this tool returns is_error and "
        "you must retry with corrections — up to 2 retries (3 total "
        "attempts) before the loop falls back to a deterministic-only "
        "report."
    ),
    AgentScanReport.model_json_schema(),
)
async def emit_report(args: dict[str, Any]) -> dict[str, Any]:
    """D-54 boundary + D-55 repair-loop trigger."""
    global _EMITTED_REPORT
    try:
        _EMITTED_REPORT = AgentScanReport.model_validate(args)
    except Exception as exc:  # pydantic.ValidationError
        return {
            "content": [{
                "type": "text",
                "text": (
                    f"VALIDATION ERROR — emit_report payload rejected. "
                    f"Please retry with corrections.\n\nDetails:\n{exc}\n\n"
                    f"Schema: {json.dumps(AgentScanReport.model_json_schema(), indent=2)}"
                ),
            }],
            "is_error": True,  # D-55 repair-loop trigger
        }
    return _wrap({"status": "ok", "message": "Report accepted; loop terminating."})


# -- registration -------------------------------------------------------

ALL_TOOLS = [
    get_git_cadence_findings,
    get_loc_inventory_findings,
    get_secret_detection_findings,
    get_doc_presence_findings,
    get_todo_markers_findings,
    get_file_size_cap_findings,
    get_tsc_diagnostics,
    get_eslint_lint,
    get_knip_dead_code,
    get_lcov_coverage,
    get_scope_ledger,
    get_meta,
    get_findings_by_dimension,
    emit_report,
]


def available_tools_for_prompt() -> list[dict[str, str]]:
    """List of {name, description} dicts for the D-56 system prompt's Section 8."""
    out: list[dict[str, str]] = []
    for t in ALL_TOOLS:
        # The @tool decorator stores the name + description on the
        # wrapped object. SDK exposes these via attributes; fall back
        # to the function's own docstring if the attribute is missing
        # under a future SDK version (Pitfall 1 — re-verify at runtime).
        name = getattr(t, "name", None) or getattr(t, "__name__", "")
        desc = getattr(t, "description", None) or (inspect.getdoc(t) or "").strip()
        out.append({"name": f"mcp__arch__{name}", "description": desc})
    return out


def build_mcp_server(
    *,
    findings: "list[Finding]",
    scope_ledger: "ScopeLedger",
    meta: "ReportMeta",
):
    """Populate _RESULTS + return the in-process MCP server.

    Called by Plan 04-06's run_agent_session() BEFORE
    ClaudeSDKClient.connect(). The returned server config is passed to
    ClaudeAgentOptions.mcp_servers={'arch': server} via Plan 04-04's
    build_options(mcp_server=...).
    """
    global _EMITTED_REPORT
    _RESULTS.update(findings=findings, scope_ledger=scope_ledger, meta=meta)
    _EMITTED_REPORT = None  # reset for this scan
    return create_sdk_mcp_server(name="arch", version="1", tools=ALL_TOOLS)


def get_emitted_report() -> AgentScanReport | None:
    """Returns the AgentScanReport from the most recent emit_report call (if any)."""
    return _EMITTED_REPORT


def reset_state() -> None:
    """Test helper: clear _RESULTS + _EMITTED_REPORT between scans."""
    global _EMITTED_REPORT
    _RESULTS.clear()
    _RESULTS.update(findings=[], scope_ledger=None, meta=None)
    _EMITTED_REPORT = None
