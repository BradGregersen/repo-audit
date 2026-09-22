"""Tests for the D-55 emit_report repair loop.

Plan 04-06 lands agent.session, so these flip from SKIPPED to ACTIVE and
exercise the repair-attempt counting + fall-through behavior of
run_agent_session() against a mocked ClaudeSDKClient.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_repair_first_attempt_succeeds_no_retry  (D-55 — first attempt valid → no retry)
- test_repair_validates_after_one_retry        (D-55 — validates after one retry)
- test_repair_exhausted_after_three_attempts   (D-55 — 3 attempts → fall through to D-67)
"""
from __future__ import annotations

import asyncio
import datetime as _dt
from unittest.mock import patch

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent.session",
    reason="optional module repo_audit.agent.session not importable — feature not present in this build, or the install is incomplete",
)

from claude_agent_sdk import (  # noqa: E402
    AssistantMessage,
    ResultMessage,
    ToolUseBlock,
)

from repo_audit.agent import tools as _tools  # noqa: E402
from repo_audit.agent.session import run_agent_session  # noqa: E402
from repo_audit.schema.detection import DetectionResult  # noqa: E402
from repo_audit.schema.report import ReportMeta  # noqa: E402


def _meta() -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=_dt.date(2026, 5, 29),
        tool_version="0.0.0",
        detected_stacks=[],
        partial=False,
    )


def _assistant(content=None) -> AssistantMessage:
    return AssistantMessage(
        content=content or [],
        model="claude-sonnet-4-5",
        usage={"input_tokens": 10, "output_tokens": 5},
    )


def _result() -> ResultMessage:
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


def _run(messages, mock_sdk_client, *, emit_on_finish=False):
    """Drive run_agent_session with a mocked ClaudeSDKClient stream.

    emit_on_finish: simulate the real emit_report handler having populated
    _EMITTED_REPORT (the success path) by setting module state after the loop
    consumes the stream but before the loop reads get_emitted_report().
    """
    _tools.reset_state()
    if emit_on_finish:
        from repo_audit.agent.schema import AgentScanReport

        _tools._EMITTED_REPORT = AgentScanReport(
            dimensions=[], executive_summary="ok", cross_cutting_notes=None
        )

    def _client_ctor(*args, **kwargs):
        return mock_sdk_client(messages)

    with patch("repo_audit.agent.session.ClaudeSDKClient", side_effect=_client_ctor):
        emitted, meta = asyncio.run(
            run_agent_session(
                findings=[],
                scope_ledger=None,
                detection=DetectionResult(stacks=[]),
                meta=_meta(),
            )
        )
    return emitted, meta


def test_repair_first_attempt_succeeds_no_retry(mock_sdk_client):
    """D-55: a valid first attempt incurs no retry → agent_status == 'ok'."""
    messages = [_assistant(content=[_emit("u1")]), _result()]
    _emitted, meta = _run(messages, mock_sdk_client, emit_on_finish=True)
    assert meta.agent_status == "ok"


def test_repair_validates_after_one_retry(mock_sdk_client):
    """D-55: report validates after exactly one retry (2 attempts) → 'ok'."""
    messages = [
        _assistant(content=[_emit("u1")]),  # failed attempt
        _assistant(content=[_emit("u2")]),  # successful retry
        _result(),
    ]
    _emitted, meta = _run(messages, mock_sdk_client, emit_on_finish=True)
    assert meta.agent_status == "ok"


def test_repair_exhausted_after_three_attempts(mock_sdk_client):
    """D-55: more than 3 attempts → fall through to unavailable_emit_report_invalid."""
    messages = [
        _assistant(content=[_emit("u1")]),
        _assistant(content=[_emit("u2")]),
        _assistant(content=[_emit("u3")]),
        _assistant(content=[_emit("u4")]),  # 4th trips the cap
        _result(),
    ]
    _emitted, meta = _run(messages, mock_sdk_client)
    assert meta.agent_status == "unavailable_emit_report_invalid"
