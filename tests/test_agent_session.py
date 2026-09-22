"""Tests for AGENT-01, AGENT-05, AGENT-06, D-55, D-65, D-67, D-68.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands. Plan 04-06 lands agent.session, so these
go ACTIVE and exercise run_agent_session() against a mocked ClaudeSDKClient.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_single_client_loop          (AGENT-01 — one ClaudeSDKClient drives the loop)
- test_token_budget_cap            (AGENT-05, D-65 — token budget cap honored)
- test_max_budget_usd_signal       (AGENT-05, D-65 — ResultMessage.subtype=='error_max_budget_usd')
- test_meta_cost_capture           (AGENT-06 — total_cost_usd captured into meta)
- test_auth_missing_fallback       (D-67 — CLINotFoundError → unavailable_auth_missing)
- test_network_fallback_after_retry(D-67/D-68 — outer retry then unavailable_network)
- test_repair_loop_exhausted       (D-55/D-67 — → unavailable_emit_report_invalid)
- test_write_attempt_blocked       (AGENT-03 — mocked-SDK behavior assertion)
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
    ToolResultBlock,
    ToolUseBlock,
)
from claude_agent_sdk._errors import (  # noqa: E402
    CLIConnectionError,
    CLINotFoundError,
    ProcessError,
)

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


def _detection() -> DetectionResult:
    return DetectionResult(stacks=[])


def _assistant(input_tokens: int, output_tokens: int, content=None) -> AssistantMessage:
    return AssistantMessage(
        content=content or [],
        model="claude-sonnet-4-5",
        usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
    )


def _result(subtype: str = "success", total_cost_usd: float | None = 0.01234) -> ResultMessage:
    return ResultMessage(
        subtype=subtype,
        duration_ms=1234,
        duration_api_ms=1000,
        is_error=subtype != "success",
        num_turns=2,
        session_id="s1",
        total_cost_usd=total_cost_usd,
    )


def _run(messages, mock_sdk_client, *, raise_on_init=None):
    """Drive run_agent_session with a mocked ClaudeSDKClient.

    raise_on_init, when set, is a callable returning the exception (or a list
    of exceptions, one per construction attempt) the patched ClaudeSDKClient
    constructor raises instead of returning the mock client.
    """
    init_calls = {"count": 0}

    def _client_ctor(*args, **kwargs):
        idx = init_calls["count"]
        init_calls["count"] += 1
        if raise_on_init is not None:
            exc = raise_on_init[idx] if isinstance(raise_on_init, list) else raise_on_init
            if exc is not None:
                raise exc
        return mock_sdk_client(messages)

    with patch("repo_audit.agent.session.ClaudeSDKClient", side_effect=_client_ctor):
        emitted, meta = asyncio.run(
            run_agent_session(
                findings=[],
                scope_ledger=None,
                detection=_detection(),
                meta=_meta(),
            )
        )
    return emitted, meta, init_calls["count"]


def _emit_use(call_id: str = "u1") -> ToolUseBlock:
    return ToolUseBlock(id=call_id, name="emit_report", input={})


def _tool_err(call_id: str = "u1") -> ToolResultBlock:
    return ToolResultBlock(tool_use_id=call_id, content="VALIDATION ERROR", is_error=True)


def test_single_client_loop(mock_sdk_client):
    """AGENT-01: a single ClaudeSDKClient drives the agent loop."""
    messages = [_assistant(100, 50), _result()]
    _emitted, meta, init_count = _run(messages, mock_sdk_client)
    assert init_count == 1
    assert meta.agent_status == "ok"


def test_token_budget_cap(mock_sdk_client):
    """AGENT-05, D-65: the token budget cap is honored (disconnect + cost_capped)."""
    # Two turns of 80k each => 160k > 150k threshold before the ResultMessage.
    messages = [_assistant(80_000, 0), _assistant(80_000, 0), _result()]
    captured = {}

    def _client(msgs):
        c = mock_sdk_client(msgs)
        captured["client"] = c
        return c

    _emitted, meta, _init = _run(messages, _client)
    assert meta.agent_status == "cost_capped"
    assert meta.token_usage == 160_000
    captured["client"].disconnect.assert_awaited()


def test_max_budget_usd_signal(mock_sdk_client):
    """AGENT-05, D-65: ResultMessage.subtype=='error_max_budget_usd' → cost_capped."""
    messages = [_assistant(100, 50), _result(subtype="error_max_budget_usd")]
    _emitted, meta, _init = _run(messages, mock_sdk_client)
    assert meta.agent_status == "cost_capped"


def test_meta_cost_capture(mock_sdk_client):
    """AGENT-06: total_cost_usd captured; token_usage cumulative; wall_clock > 0."""
    messages = [_assistant(100, 50), _assistant(40, 10), _result(total_cost_usd=0.0777)]
    _emitted, meta, _init = _run(messages, mock_sdk_client)
    assert meta.total_cost_usd == 0.0777
    assert meta.token_usage == 200  # 150 + 50
    assert meta.wall_clock_seconds is not None and meta.wall_clock_seconds > 0


def test_auth_missing_fallback(mock_sdk_client):
    """D-67: CLINotFoundError → unavailable_auth_missing; no retry attempted."""
    _emitted, meta, init_count = _run(
        [], mock_sdk_client, raise_on_init=CLINotFoundError("cli not found")
    )
    assert meta.agent_status == "unavailable_auth_missing"
    assert init_count == 1  # terminal — no retry


def test_network_fallback_after_retry(mock_sdk_client):
    """D-67/D-68: CLIConnectionError twice → unavailable_network; 2 init attempts."""
    _emitted, meta, init_count = _run(
        [],
        mock_sdk_client,
        raise_on_init=[CLIConnectionError("net"), CLIConnectionError("net")],
    )
    assert meta.agent_status == "unavailable_network"
    assert init_count == 2  # initial + 1 outer retry


def test_process_error_with_auth_stderr_is_auth_missing(mock_sdk_client):
    """D-67: ProcessError with auth-pattern stderr → unavailable_auth_missing."""
    _emitted, meta, _init = _run(
        [],
        mock_sdk_client,
        raise_on_init=ProcessError("boom", exit_code=1, stderr="Unauthorized: please sign in"),
    )
    assert meta.agent_status == "unavailable_auth_missing"


def test_process_error_without_auth_stderr_is_sdk_exception(mock_sdk_client):
    """D-67: ProcessError with non-auth stderr → unavailable_sdk_exception."""
    _emitted, meta, _init = _run(
        [],
        mock_sdk_client,
        raise_on_init=ProcessError("boom", exit_code=2, stderr="disk full"),
    )
    assert meta.agent_status == "unavailable_sdk_exception"


def test_repair_loop_exhausted(mock_sdk_client):
    """D-55/D-67: 3 failed emit_report attempts → unavailable_emit_report_invalid."""
    from repo_audit.agent import tools as _tools

    _tools.reset_state()
    messages = [
        _assistant(10, 5, content=[_emit_use("u1")]),
        _assistant(10, 5, content=[_emit_use("u2")]),
        _assistant(10, 5, content=[_emit_use("u3")]),
        _assistant(10, 5, content=[_emit_use("u4")]),  # 4th attempt trips the cap
        _result(),
    ]
    _emitted, meta, _init = _run(messages, mock_sdk_client)
    assert meta.agent_status == "unavailable_emit_report_invalid"
    assert _tools.get_emitted_report() is None


def test_write_attempt_blocked(mock_sdk_client):
    """AGENT-03: a Write ToolUseBlock in the stream does not derail the loop.

    allowed_tools (Plan 04-04) excludes Write; the SDK refuses the invocation
    before our loop sees a successful result. Our loop just keeps tallying and
    terminates normally on ResultMessage.
    """
    messages = [
        _assistant(100, 50, content=[ToolUseBlock(id="w1", name="Write", input={})]),
        _result(),
    ]
    _emitted, meta, _init = _run(messages, mock_sdk_client)
    assert meta.agent_status == "ok"
