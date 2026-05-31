"""Tests for the in-session completion-honesty repair hook (quick 260530-tbi).

The honesty check is hooked INSIDE the emit_report tool handler so that, on a
PARTIAL scan, a narrative containing a standalone all/every/complete token
returns {is_error: True} (the D-55 repair signal) instead of being accepted and
then hard-refused at render time (renderer.py rc=3). The four locked behaviors:

1. partial + forbidden token  -> is_error, tokens named, _EMITTED_REPORT stays None
2. non-partial + forbidden     -> accepted (gate is a no-op when partial=False)
3. partial + qualified prose    -> accepted, _EMITTED_REPORT set
4. four emit_report attempts    -> unavailable_emit_report_invalid (the existing
   _MAX_EMIT_REPORT_ATTEMPTS cap bounds honesty rejections with NO session.py change)
"""
from __future__ import annotations

import asyncio
import datetime as _dt

import pytest

_tools = pytest.importorskip(
    "repo_audit.agent.tools",
    reason="Phase 4 agent.tools required",
)

from repo_audit.agent.session import run_agent_session  # noqa: E402
from repo_audit.schema.detection import DetectionResult  # noqa: E402
from repo_audit.schema.report import ReportMeta  # noqa: E402


def _meta(partial: bool) -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=_dt.date(2026, 5, 29),
        tool_version="0.0.0",
        detected_stacks=[],
        partial=partial,
    )


def _args(narrative: str, executive_summary: str = "") -> dict:
    return {
        "dimensions": [
            {
                "dimension": "security",
                "narrative": narrative,
                "severity_calls": [],
            }
        ],
        "executive_summary": executive_summary,
        "cross_cutting_notes": None,
    }


def _invoke(args: dict) -> dict:
    # The @tool decorator wraps emit_report as an SdkMcpTool dataclass whose
    # async function is exposed on `.handler` (Plan 04-05 SUMMARY); invoke it
    # exactly as the live in-process MCP server would.
    return asyncio.run(_tools.emit_report.handler(args))


def test_partial_scan_forbidden_token_returns_is_error():
    _tools.reset_state()
    _tools._RESULTS["meta"] = _meta(partial=True)

    result = _invoke(
        _args("This covers every dimension and all findings were reviewed.")
    )

    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "every" in text.lower()
    assert "all" in text.lower()
    # A rejected emit must NOT leave a stored report — the loop must not
    # terminate with a dirty report.
    assert _tools.get_emitted_report() is None


def test_non_partial_scan_forbidden_token_accepted():
    _tools.reset_state()
    _tools._RESULTS["meta"] = _meta(partial=False)

    result = _invoke(
        _args("This covers every dimension and all findings were reviewed.")
    )

    assert not result.get("is_error")
    assert _tools.get_emitted_report() is not None


def test_partial_scan_qualified_narrative_accepted():
    _tools.reset_state()
    _tools._RESULTS["meta"] = _meta(partial=True)

    result = _invoke(
        _args(
            "The in-scope dimensions show clean results; the collected "
            "findings are limited.",
            executive_summary=(
                "As far as the scan reached, the collected findings are few."
            ),
        )
    )

    assert not result.get("is_error")
    assert _tools.get_emitted_report() is not None


def test_meta_none_skips_check_and_accepts():
    """Defensive: meta missing -> honesty check skipped, no crash, accepted."""
    _tools.reset_state()
    # meta stays None after reset_state.
    result = _invoke(
        _args("This covers every dimension and all findings were reviewed.")
    )

    assert not result.get("is_error")
    assert _tools.get_emitted_report() is not None


def test_cap_bounds_repeated_honesty_failures(mock_sdk_client):
    """The existing _MAX_EMIT_REPORT_ATTEMPTS cap bounds repeated emit_report
    ToolUseBlocks regardless of WHY each was rejected (honesty or schema).

    This confirms session.py needs NO change: it counts emit_report
    ToolUseBlocks, so honesty-driven is_error rejections are bounded by the
    same machinery as schema-driven ones.
    """
    from unittest.mock import patch

    from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock

    def _assistant(content):
        return AssistantMessage(
            content=content,
            model="claude-sonnet-4-5",
            usage={"input_tokens": 10, "output_tokens": 5},
        )

    def _result():
        return ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=False,
            num_turns=1,
            session_id="s1",
            total_cost_usd=0.001,
        )

    def _emit(call_id: str) -> ToolUseBlock:
        return ToolUseBlock(id=call_id, name="emit_report", input={})

    messages = [
        _assistant(content=[_emit("u1")]),
        _assistant(content=[_emit("u2")]),
        _assistant(content=[_emit("u3")]),
        _assistant(content=[_emit("u4")]),  # 4th trips the cap
        _result(),
    ]

    _tools.reset_state()

    def _client_ctor(*args, **kwargs):
        return mock_sdk_client(messages)

    with patch(
        "repo_audit.agent.session.ClaudeSDKClient", side_effect=_client_ctor
    ):
        _emitted, meta = asyncio.run(
            run_agent_session(
                findings=[],
                scope_ledger=None,
                detection=DetectionResult(stacks=[]),
                meta=_meta(partial=True),
            )
        )

    assert meta.agent_status == "unavailable_emit_report_invalid"
