"""The agent loop — single ClaudeSDKClient per scan (D-53).

run_agent_session() is the only entry point cli.py calls. It owns:
  - D-53 single ClaudeSDKClient loop
  - D-65 in-loop token tally + client.disconnect() on threshold
  - D-55 repair loop on emit_report validation failure (max 3 attempts)
  - D-68 outer retry (1 retry, 2-second sleep)
  - D-67 exception taxonomy mapping → meta.agent_status

All paths return a (AgentScanReport | None, ReportMeta) tuple. Plan 04-08's
renderer reads meta.agent_status to choose between the agent-narrative
render path (ok) and the deterministic-only pending-marker render path
(every other status). Exit code is 0 in EVERY case — D-67 mandates
graceful fallback.

Imports of `claude_agent_sdk` are at module top because session.py is
only imported lazily by cli.py's scan command when the agent step is
requested (--no-agent skips this module entirely). Other plans can
still import session.py for type-checking via the TYPE_CHECKING block.
"""
from __future__ import annotations

import asyncio
import re
import sys
import time
from typing import TYPE_CHECKING

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKClient,
    ResultMessage,
    ToolResultBlock,  # noqa: F401 — part of the documented loop interface (D-55)
    ToolUseBlock,
)
from claude_agent_sdk._errors import (
    ClaudeSDKError,
    CLIConnectionError,
    CLINotFoundError,
    ProcessError,
)

from repo_audit.agent.constants import get_threshold
from repo_audit.agent.options import build_options
from repo_audit.agent.tools import (
    available_tools_for_prompt,
    build_mcp_server,
    get_emitted_report,
    reset_state,
)

if TYPE_CHECKING:
    from repo_audit.agent.schema import AgentScanReport
    from repo_audit.schema.detection import DetectionResult
    from repo_audit.schema.finding import Finding
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger


# D-67 exception-stderr pattern (RESEARCH §"Exception hierarchy"):
# ProcessError with auth-related stderr → 'unavailable_auth_missing'
_AUTH_STDERR_PATTERN = re.compile(r"auth|unauthorized|forbidden|sign in", re.IGNORECASE)

# D-55 cap: 3 total attempts (1 initial + 2 retries)
_MAX_EMIT_REPORT_ATTEMPTS = 3


async def run_agent_session(
    *,
    findings: "list[Finding]",
    scope_ledger: "ScopeLedger",
    detection: "DetectionResult",
    meta: "ReportMeta",
    trend: "object | None" = None,
    top_findings: "object | None" = None,
) -> tuple["AgentScanReport | None", "ReportMeta"]:
    """Run the agent loop. Returns (emitted_report_or_None, mutated_meta).

    meta is mutated in place AND returned for explicitness. The caller
    (cli.py / Plan 04-09) discards the return-tuple meta and uses the
    mutation directly — both spellings work.
    """
    wall_clock_start = time.perf_counter()
    reset_state()

    # Plan 04-05 contract: returns the McpServerConfig + populates _RESULTS.
    # Plan 18-03: the pre-ranked Top-N shortlist is handed in so the agent can
    # fill ONLY why_it_matters per item (Python rank/score/ids stay authoritative).
    mcp_server = build_mcp_server(
        findings=findings, scope_ledger=scope_ledger, meta=meta, trend=trend,
        top_findings=top_findings,
    )

    options = build_options(
        detection=detection,
        repo_name=meta.repo_slug,
        partial=meta.partial,
        mcp_server=mcp_server,
        available_tools_for_prompt=available_tools_for_prompt(),
    )

    max_tokens = get_threshold("agent.max_tokens_per_scan")  # D-65 default 150_000
    running_tokens = 0
    emit_report_attempts = 0
    agent_status: str = "ok"
    sdk_total_cost_usd: float | None = None

    # D-68 outer retry: 2 attempts max.
    for attempt in range(2):
        try:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(
                    "Scan complete. Inspect the findings via the tool getters, "
                    "then call emit_report exactly once with the structured "
                    "AgentScanReport payload."
                )
                async for msg in client.receive_messages():
                    # D-65 token tally — every AssistantMessage with usage.
                    if isinstance(msg, AssistantMessage) and msg.usage:
                        # RESEARCH Assumption A6 — defensive .get() against
                        # SDK reshape of the usage dict keys.
                        input_tokens = msg.usage.get("input_tokens", 0)
                        output_tokens = msg.usage.get("output_tokens", 0)
                        if not isinstance(input_tokens, int):
                            input_tokens = 0
                        if not isinstance(output_tokens, int):
                            output_tokens = 0
                        running_tokens += input_tokens + output_tokens

                        # D-55 repair-loop counter — inspect ToolUseBlocks
                        # for emit_report invocations.
                        for block in (msg.content or []):
                            if isinstance(block, ToolUseBlock) and block.name == "emit_report":
                                emit_report_attempts += 1

                        # D-65 in-loop disconnect on threshold cross.
                        if running_tokens >= max_tokens:
                            await client.disconnect()
                            agent_status = "cost_capped"
                            break

                        # D-55 repair-cap check.
                        if emit_report_attempts > _MAX_EMIT_REPORT_ATTEMPTS:
                            await client.disconnect()
                            agent_status = "unavailable_emit_report_invalid"
                            break

                    elif isinstance(msg, ResultMessage):
                        # D-65 USD capture + max_budget_usd signal.
                        if msg.subtype == "error_max_budget_usd":
                            agent_status = "cost_capped"
                        sdk_total_cost_usd = msg.total_cost_usd
                        # ResultMessage means the SDK is done.
                        break
            # If we exit the async-with cleanly, break the outer retry.
            break

        except CLINotFoundError:
            agent_status = "unavailable_auth_missing"
            print(
                "agent: unavailable_auth_missing — Claude Code CLI binary not found",
                file=sys.stderr,
            )
            break  # no retry — auth failure is terminal

        except CLIConnectionError:
            if attempt == 1:  # outer retry exhausted (D-68)
                agent_status = "unavailable_network"
                print(
                    "agent: unavailable_network — SDK transport failed after retry",
                    file=sys.stderr,
                )
                break
            # First failure — sleep and retry per D-68.
            await asyncio.sleep(2)
            continue

        except ProcessError as exc:
            stderr_text = str(getattr(exc, "stderr", "")) or str(exc)
            if _AUTH_STDERR_PATTERN.search(stderr_text):
                agent_status = "unavailable_auth_missing"
                print(
                    f"agent: unavailable_auth_missing — {type(exc).__name__}",
                    file=sys.stderr,
                )
            else:
                agent_status = "unavailable_sdk_exception"
                print(
                    f"agent: unavailable_sdk_exception — {type(exc).__name__}",
                    file=sys.stderr,
                )
            break

        except ClaudeSDKError as exc:
            agent_status = "unavailable_sdk_exception"
            print(
                f"agent: unavailable_sdk_exception — {type(exc).__name__}",
                file=sys.stderr,
            )
            break

    # Populate meta (D-65 / AGENT-06 / D-67).
    meta.agent_status = agent_status
    meta.token_usage = running_tokens
    meta.total_cost_usd = sdk_total_cost_usd
    meta.wall_clock_seconds = time.perf_counter() - wall_clock_start

    emitted = get_emitted_report() if agent_status == "ok" else None
    # On cost_capped we may still have a partial emit_report; surface it
    # so Plan 04-08's renderer can decide whether to honor it. D-65:
    # "partial narrative present (whatever made it before disconnect)".
    if agent_status == "cost_capped":
        emitted = get_emitted_report()

    return emitted, meta
