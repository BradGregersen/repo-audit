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
from collections import Counter
from typing import TYPE_CHECKING, Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from repo_audit.agent.schema import AgentScanReport
from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
)

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger


# -- bounded-aggregate constants (quick task 260530-pjq) ----------------
# top_n cap for representative findings in every finding-list getter summary.
TOP_N: int = 12

# Severity rank for ranking — lower = more severe → sorts first. Mirrors the
# Severity Literal order in schema/enums.py.
_SEVERITY_RANK: dict[str, int] = {
    "blocker": 0,
    "critical": 1,
    "major": 2,
    "minor": 3,
    "info": 4,
}

# All five severity keys, present-with-zeros for a stable summary shape.
_ALL_SEVERITIES: tuple[str, ...] = ("blocker", "critical", "major", "minor", "info")

# Per-finding snippet excerpt cap inside top_n. The schema already redacts +
# caps output_snippet at 2048 chars; we excerpt further so TOP_N representative
# snippets cannot dominate the bounded summary (12 × 2048 ≈ 25 KB defeats the
# whole point). A few hundred chars is plenty for the narrator to characterize.
_TOP_N_SNIPPET_CAP: int = 280


# Module-level state the session loop populates before connect().
_RESULTS: dict[str, Any] = {
    "findings": [],
    "scope_ledger": None,
    "meta": None,
    "trend": None,
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


def _summarize(findings: "list[Finding]") -> dict[str, Any]:
    """Deterministic, HARD-bounded aggregate of a finding list (260530-pjq).

    Replaces the prior "json.dumps the entire list" getter payload — which
    overflowed the SDK tool-result / context budget on large collectors (knip
    arch-rot ~2,836 findings on adapt) and left the agent narrating from counts
    only. The returned dict is bounded in serialized size REGARDLESS of input
    cardinality:

      - "total": len(findings).
      - "counts_by_severity": all 5 severities present (zeros included) → int;
        sums to total. Stable shape.
      - "counts_by_rule": rule_id → int. The ONE potentially-unbounded field, so
        it is capped: the top (TOP_N * 4) most-frequent rule_ids are kept and the
        remainder folded into a single "__other__" bucket so the values STILL sum
        to total and the field stays bounded regardless of rule cardinality.
      - "top_n": <= TOP_N representative finding dicts carrying ONLY
        {severity, rule_id, file, line, snippet}. snippet is the schema's already
        redacted output_snippet, further excerpted to _TOP_N_SNIPPET_CAP chars so
        TOP_N snippets cannot dominate the bounded payload (never re-expanded). No
        full model_dump.

    Ranking for top_n (computed here in Python — the agent never ranks/invents):
      (a) severity rank ascending via _SEVERITY_RANK (blocker first),
      (b) rule_id frequency DESCENDING (most-common rule first),
      (c) stable deterministic tie-break: (file or "", line or -1, rule_id).
    The full sort key is value-derived (no reliance on input order), so a
    shuffled copy of the same findings yields the same top_n (CLAUDE.md
    reproducibility).
    """
    total = len(findings)

    counts_by_severity: dict[str, int] = {s: 0 for s in _ALL_SEVERITIES}
    rule_counter: Counter[str] = Counter()
    for f in findings:
        sev = getattr(f, "severity", "")
        if sev in counts_by_severity:
            counts_by_severity[sev] += 1
        rule_counter[getattr(f, "rule_id", "") or ""] += 1

    # Cap counts_by_rule: keep the TOP_N*4 most frequent, fold the rest into
    # __other__ so the values still sum to total.
    rule_cap = TOP_N * 4
    counts_by_rule: dict[str, int] = {}
    if len(rule_counter) <= rule_cap:
        counts_by_rule = dict(rule_counter)
    else:
        # most_common is order-stable on ties by insertion; sort the kept set
        # deterministically for a reproducible payload.
        kept = sorted(rule_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:rule_cap]
        counts_by_rule = dict(kept)
        other = total - sum(counts_by_rule.values())
        if other:
            counts_by_rule["__other__"] = other

    # Rank for top_n. Frequency is over the FULL counter (not the capped map) so
    # representative selection reflects true rule prevalence.
    ranked = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(getattr(f, "severity", ""), len(_SEVERITY_RANK)),
            -rule_counter[getattr(f, "rule_id", "") or ""],
            getattr(f, "file", None) or "",
            getattr(f, "line", None) if getattr(f, "line", None) is not None else -1,
            getattr(f, "rule_id", "") or "",
        ),
    )
    top_n = [
        {
            "severity": getattr(f, "severity", ""),
            "rule_id": getattr(f, "rule_id", "") or "",
            "file": getattr(f, "file", None),
            "line": getattr(f, "line", None),
            "snippet": (getattr(getattr(f, "evidence", None), "output_snippet", "") or "")[
                :_TOP_N_SNIPPET_CAP
            ],
        }
        for f in ranked[:TOP_N]
    ]

    return {
        "total": total,
        "counts_by_severity": counts_by_severity,
        "counts_by_rule": counts_by_rule,
        "top_n": top_n,
    }


def _findings_by_source_tool(source_tool: str) -> dict[str, Any]:
    matched = [
        f
        for f in _RESULTS.get("findings", [])
        if getattr(f, "source_tool", "") == source_tool
    ]
    return _summarize(matched)


def _findings_by_source_collector(source_collector: str) -> dict[str, Any]:
    matched = [
        f
        for f in _RESULTS.get("findings", [])
        if getattr(f, "source_collector", "") == source_collector
    ]
    return _summarize(matched)


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
    matched = [
        f
        for f in _RESULTS.get("findings", [])
        if getattr(f, "dimension", "") == dim
    ]
    return _wrap(_summarize(matched))


# -- trend baseline getter (Plan 05-03 / TREND-02) ----------------------

@tool(
    "trend_baseline",
    _module_description("repo_audit.trend.delta"),
    {"_unused": str},
)
async def trend_baseline(args: dict[str, Any]) -> dict[str, Any]:
    """Returns the Python-computed TrendDelta vs the prior sidecar.

    The deltas are computed DETERMINISTICALLY by ``trend.delta.compute_trend``
    BEFORE the agent runs — the agent reads them here and narrates ONLY these
    numbers into ``AgentScanReport.trend_narrative`` (TREND-02 / D-05-07:
    never invent trend numbers). On a baseline run (no prior sidecar) the
    payload is ``{"baseline_run": true}`` and the agent leaves
    ``trend_narrative`` null.
    """
    return _wrap(_RESULTS.get("trend") or {"baseline_run": True})


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
    """D-54 boundary + D-55 repair-loop trigger.

    Two ``is_error`` returns drive the D-55 repair loop:
      1. schema-validation failure (model_validate raises), and
      2. completion-honesty violation on a PARTIAL scan (quick 260530-tbi).

    The honesty gate is hooked here so a partial-scan narrative tripping the
    standalone all/every/complete check becomes an IN-SESSION repair signal
    instead of a terminal render-time refusal (renderer.py rc=3). The
    render-time completion_honesty_lint backstop in renderer.py is KEPT
    unchanged as the authoritative defense-in-depth layer.

    CRITICAL: validate into a LOCAL first and only assign ``_EMITTED_REPORT``
    AFTER the honesty gate passes (or is skipped because meta is None) — a
    rejected emit must leave ``_EMITTED_REPORT`` unset for this scan so the
    session loop never terminates with a dirty report.
    """
    global _EMITTED_REPORT
    try:
        report = AgentScanReport.model_validate(args)
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

    # In-session completion-honesty gate (quick 260530-tbi). Skipped when meta
    # is absent (defensive — never crash). Otherwise lint the SAME buffer the
    # renderer builds (renderer.py 206-209: dimension narratives FIRST, then
    # executive_summary) so an in-session repair actually prevents the
    # render-time rc=3.
    meta = _RESULTS.get("meta")
    if meta is not None:
        agent_narrative_buf = "\n\n".join(
            [dim.narrative for dim in report.dimensions]
            + [report.executive_summary or ""]
        )
        try:
            completion_honesty_lint(
                agent_narrative_buf,
                partial=meta.partial,
                buffer_name="agent-narrative",
            )
        except CompletionHonestyViolation as exc:
            # Do NOT store _EMITTED_REPORT — leave it unset for this scan so
            # the session loop does not terminate with a dirty report.
            tokens = sorted({h.word for h in exc.hits})
            return {
                "content": [{"type": "text", "text": (
                    "COMPLETION-HONESTY VIOLATION — emit_report rejected on a "
                    "PARTIAL scan. These standalone words are forbidden in the "
                    f"narrative on a partial scan: {tokens}. Rewrite to qualify "
                    "scope — say 'the in-scope dimensions' not 'every dimension', "
                    "'the collected findings' not 'all findings', 'as far as the "
                    "scan reached' not 'complete' — and call emit_report again."
                )}],
                "is_error": True,  # D-55 repair-loop trigger (same shape as schema path)
            }

    _EMITTED_REPORT = report
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
    trend_baseline,
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
    trend: "object | None" = None,
):
    """Populate _RESULTS + return the in-process MCP server.

    Called by Plan 04-06's run_agent_session() BEFORE
    ClaudeSDKClient.connect(). The returned server config is passed to
    ClaudeAgentOptions.mcp_servers={'arch': server} via Plan 04-04's
    build_options(mcp_server=...).

    ``trend`` (Plan 05-03) is the deterministic ``TrendDelta`` for this scan
    (or None on a baseline run). It is JSON-serialized and stashed so the
    ``trend_baseline`` getter can hand the agent the Python-computed deltas
    to narrate (TREND-02). None → the getter returns ``{"baseline_run": True}``.
    """
    global _EMITTED_REPORT
    _RESULTS.update(
        findings=findings,
        scope_ledger=scope_ledger,
        meta=meta,
        trend=(trend.model_dump(mode="json") if trend is not None else None),
    )
    _EMITTED_REPORT = None  # reset for this scan
    return create_sdk_mcp_server(name="arch", version="1", tools=ALL_TOOLS)


def get_emitted_report() -> AgentScanReport | None:
    """Returns the AgentScanReport from the most recent emit_report call (if any)."""
    return _EMITTED_REPORT


def reset_state() -> None:
    """Test helper: clear _RESULTS + _EMITTED_REPORT between scans."""
    global _EMITTED_REPORT
    _RESULTS.clear()
    _RESULTS.update(findings=[], scope_ledger=None, meta=None, trend=None)
    _EMITTED_REPORT = None
