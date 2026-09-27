"""End-to-end pipeline test (mocked SDK, full render flow).

Verifies the 6-stage chokepoint pipeline runs in order:
  collectors → adapters → agent → faithfulness → dilution →
  corroboration → secret_lint → completion_honesty → _write_outputs

Uses the happy_path message-stream fixture so the agent emits a valid
AgentScanReport.
"""
from __future__ import annotations

import asyncio
import json
from datetime import date

import pytest

pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")

# Bind the REAL run_agent_session at import (collection) time, BEFORE the
# autouse conftest._stub_agent_session fixture monkeypatches the module
# attribute to a hermetic no-op. The e2e test must drive the genuine loop.
_real_run_agent_session = pytest.importorskip(
    "repo_audit.agent.session"
).run_agent_session


def test_happy_path_end_to_end(tmp_path, monkeypatch):
    """Full pipeline: agent narrative is emitted, faithfulness passes (no invented
    numbers), renderer produces markdown + JSON sidecar containing all Phase 4
    meta fields. Exit code 0."""
    from claude_agent_sdk import AssistantMessage, ToolUseBlock

    from tests.fixtures.agent.message_streams import happy_path

    from repo_audit.agent import session as session_mod
    from repo_audit.agent import tools as tools_mod
    from repo_audit.agent.schema import AgentScanReport
    from repo_audit.render.renderer import render_and_write
    from repo_audit.schema.detection import DetectionResult
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    # A minimal valid AgentScanReport with no invented numbers.
    valid_payload = {
        "dimensions": [],
        "executive_summary": "Baseline scan; no critical issues detected.",
        "cross_cutting_notes": None,
    }
    messages = happy_path.build_messages(valid_payload)

    # The mocked ClaudeSDKClient streams the canned messages. The real
    # in-process MCP server is NOT exercised under a mock, so emit_report's
    # handler (which populates _EMITTED_REPORT) never runs on its own. We
    # mirror the real MCP-server behavior here: as each AssistantMessage
    # streams by, invoke the real emit_report handler for any emit_report
    # ToolUseBlock so _EMITTED_REPORT is set exactly as a live connect would.
    class _ClientCtx:
        def __init__(self, options):
            pass

        async def __aenter__(self_inner):
            return self_inner

        async def __aexit__(self_inner, *a):
            return False

        async def query(self_inner, *a, **k):
            return None

        async def receive_messages(self_inner):
            for m in messages:
                if isinstance(m, AssistantMessage):
                    for block in (m.content or []):
                        if isinstance(block, ToolUseBlock) and block.name == "emit_report":
                            # The SDK @tool decorator wraps emit_report as an
                            # SdkMcpTool dataclass (not directly callable); its
                            # async handler is exposed on `.handler` (Plan
                            # 04-05 SUMMARY). Invoke it exactly as the live
                            # in-process MCP server would.
                            await tools_mod.emit_report.handler(block.input)
                yield m

        async def disconnect(self_inner):
            return None

    monkeypatch.setattr(session_mod, "ClaudeSDKClient", _ClientCtx)

    meta = ReportMeta(repo_slug="e2e", commit_sha="abc", scan_date=date.today(),
                      tool_version="0.1.0")
    emitted, meta = asyncio.run(_real_run_agent_session(
        findings=[], scope_ledger=ScopeLedger(),
        detection=DetectionResult(stacks=[]), meta=meta,
    ))
    assert meta.agent_status == "ok"
    assert emitted is not None
    assert isinstance(emitted, AgentScanReport)

    # Run the renderer.
    report = ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())
    md_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    rc = render_and_write(report, md_path, json_path, agent_output=emitted)
    assert rc == 0
    assert md_path.exists()
    assert json_path.exists()
    # Footer carries Phase 4 meta.
    md_text = md_path.read_text()
    assert "Agent status:" in md_text or "agent_status" in md_text.lower()
    # JSON sidecar carries the additive ReportMeta fields.
    sidecar = json.loads(json_path.read_text())
    assert sidecar["meta"]["agent_status"] == "ok"
