"""ROADMAP Phase 4 success criteria — six dedicated structural tests.

Each test binds one SC-N truth from ROADMAP §"Phase 4: AI Orchestration"
to an automated assertion. SC-3 (the load-bearing "73%" test) is also
covered at the unit level by tests/test_faithfulness_gate.py; this file
asserts the same property at the full-pipeline level via the
sc3_invented_73 fixture.
"""
from __future__ import annotations

import asyncio
from datetime import date

import pytest

pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")

# Bind the REAL run_agent_session at import (collection) time, BEFORE the
# autouse conftest._stub_agent_session fixture monkeypatches the module
# attribute to a hermetic no-op. SC-5 must drive the genuine loop (token
# tally + cost_capped path), so it calls this captured reference rather than
# the stubbed session_mod.run_agent_session.
_real_run_agent_session = pytest.importorskip(
    "repo_audit.agent.session"
).run_agent_session


# --- SC-1 ----------------------------------------------------------------

def test_sc1_no_write_bash_in_options(tmp_path):
    """SC-1: tools=[] + allowed_tools NEVER contains Write/Bash/Read/Edit."""
    import repo_audit.adapters.typescript as _ts  # noqa: F401 — register adapter
    from repo_audit.agent.options import build_options
    from repo_audit.agent.tools import available_tools_for_prompt, build_mcp_server
    from repo_audit.schema.detection import DetectionResult, StackProfile
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger

    detection = DetectionResult(stacks=[
        StackProfile(stack="typescript-node", root_dir=tmp_path, manifests=[],
                     confidence=0.95),
    ])
    meta = ReportMeta(
        repo_slug="test", commit_sha="abc", scan_date=date.today(),
        tool_version="0.1.0",
    )
    server = build_mcp_server(findings=[], scope_ledger=ScopeLedger(), meta=meta)
    options = build_options(
        detection=detection,
        repo_name="test",
        partial=False,
        mcp_server=server,
        available_tools_for_prompt=available_tools_for_prompt(),
    )
    assert options.tools == [], f"SC-1: options.tools must be [], got {options.tools!r}"
    forbidden = {"Write", "Bash", "Read", "Edit", "WebSearch", "WebFetch",
                 "NotebookEdit", "TodoWrite"}
    leaked = forbidden & set(options.allowed_tools)
    assert not leaked, f"SC-1: forbidden tools leaked into allowed_tools: {leaked}"
    # And the stack-applicable mcp tools ARE there.
    assert "mcp__arch__emit_report" in options.allowed_tools
    assert any("get_tsc_diagnostics" in t for t in options.allowed_tools)


# --- SC-2 ----------------------------------------------------------------

def test_sc2_exec_summary_corroboration(tmp_path):
    """SC-2: deterministic header + corroboration classification."""
    from repo_audit.render.corroboration import (
        classify_critical_finding, is_corroborated,
    )
    from repo_audit.render.exec_summary import build_deterministic_exec_header
    from repo_audit.schema.finding import Evidence, Finding

    # Two findings, same dim + same file, different source_tools → corroborated.
    f_tsc = Finding(
        dimension="quality", severity="critical", source_tool="tsc",
        source_collector="typescript-node", rule_id="TS2345",
        file="src/auth.ts", line=12,
        evidence=Evidence(tool="tsc", output_snippet="type error"),
        confidence="high", evidence_type="static",
        confidence_caveat="Static AST match; runtime path not verified.",
    )
    f_eslint = Finding(
        dimension="quality", severity="critical", source_tool="eslint",
        source_collector="typescript-node", rule_id="no-eval",
        file="src/auth.ts", line=15,
        evidence=Evidence(tool="eslint", output_snippet="no-eval"),
        confidence="high", evidence_type="static",
        confidence_caveat="Static AST match; runtime path not verified.",
    )
    assert is_corroborated(f_tsc, [f_tsc, f_eslint]) is True
    assert classify_critical_finding(f_tsc, [f_tsc, f_eslint]) == "critical-corroborated"

    # Single-tool critical with caveat → uncorroborated-with-caveat.
    f_lone = Finding(
        dimension="security", severity="critical", source_tool="gitleaks",
        source_collector="secret_detection", rule_id="aws-access-key",
        file="src/config.ts", line=42,
        evidence=Evidence(tool="gitleaks", output_snippet="[REDACTED:20]"),
        confidence="high", evidence_type="heuristic",
        confidence_caveat="Single tool; corroboration not available.",
    )
    assert is_corroborated(f_lone, [f_lone, f_tsc, f_eslint]) is False
    assert classify_critical_finding(f_lone, [f_lone, f_tsc, f_eslint]) == "critical-uncorroborated-with-caveat"

    # Deterministic exec header.
    header = build_deterministic_exec_header([f_tsc, f_eslint, f_lone])
    assert header.startswith("**0 blocker, 3 critical finding(s)**")
    assert "across" in header and "dimension(s)" in header


# --- SC-3 (the LOAD-BEARING structural proof) ---------------------------

def test_sc3_invented_73_pct_stripped():
    """SC-3: 'Coverage is 73%' adversarial sentence MUST strip at render.

    Uses a small-cardinals-only AllowedNumbers set (the proven seed from
    tests/test_faithfulness_gate.py) — nothing within 5% of 73 is allowed,
    so the sentence strips. NOTE: deliberately NOT using
    allowed_numbers_factory here, because that factory seeds 73.4 (an LCOV
    sample) which IS within 5% of 73 and would make this gate PASS the
    sentence — masking the very property SC-3 must prove.
    """
    from repo_audit.render.faithfulness import (
        check_faithfulness, load_faithfulness_allowlist,
    )

    trigger, allowlist = load_faithfulness_allowlist()
    # Small cardinals only: 0..7 — nothing within 5% of 73.
    allowed = {float(i) for i in range(8)}
    clean, violations = check_faithfulness(
        "Coverage is 73% across the suite.",
        allowed, trigger, allowlist, tolerance=0.05,
        dimension="test_integrity",
    )
    # Sentence stripped: clean is empty or just the collapse marker.
    assert "73%" not in clean
    assert len(violations) == 1
    assert any("73" in t for t in violations[0].offending_tokens)


# --- SC-4 ----------------------------------------------------------------

def test_sc4_missing_collector_auto_filled(tmp_path):
    """SC-4: missing required_collector triggers D-60 auto-fill."""
    import repo_audit.collectors  # noqa: F401  # populate registry
    from repo_audit.orchestration import auto_fill_ledger_gaps
    from repo_audit.schema.detection import DetectionResult
    from repo_audit.schema.scope_ledger import ScopeLedger

    # Construct empty ledger + empty findings = every required_collector missing.
    scope_ledger = ScopeLedger()
    detection = DetectionResult(stacks=[])  # no adapter; only UNIVERSAL_REQUIRED
    # Provide minimal walker_index (the collectors' run() reads it).
    new_findings, new_ledger = auto_fill_ledger_gaps(
        findings=[], scope_ledger=scope_ledger, detection=detection,
        repo_path=tmp_path, walker_index={},
    )
    # scope_ledger.notes must record the gap-fill events.
    for name in ("git_cadence", "loc_inventory", "doc_presence"):
        assert f"gap auto-filled: {name}" in new_ledger.notes, (
            f"expected gap-fill note for {name} in {new_ledger.notes!r}"
        )


# --- SC-5 ----------------------------------------------------------------

def test_sc5_cost_cap_partial_report(tmp_path, mock_sdk_client, monkeypatch):
    """SC-5: token-budget exhaustion → cost_capped + partial report + exit 0."""
    from tests.fixtures.agent.message_streams import sc5_token_capped

    from repo_audit.agent import session as session_mod
    from repo_audit.schema.detection import DetectionResult
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger

    # Patch ClaudeSDKClient so it returns our mocked client.
    canned = mock_sdk_client(messages=sc5_token_capped.build_messages(150_000))

    class _ClientCtx:
        def __init__(self, options):
            pass

        async def __aenter__(self_inner):
            return canned

        async def __aexit__(self_inner, *a):
            return False

        async def query(self_inner, *a, **k):
            return None

        def receive_messages(self_inner):
            return canned.receive_messages()

        async def disconnect(self_inner):
            return None

    monkeypatch.setattr(session_mod, "ClaudeSDKClient", _ClientCtx)

    meta = ReportMeta(repo_slug="x", commit_sha="abc", scan_date=date.today(),
                      tool_version="0.1.0")
    emitted, meta_out = asyncio.run(_real_run_agent_session(
        findings=[], scope_ledger=ScopeLedger(),
        detection=DetectionResult(stacks=[]), meta=meta,
    ))
    assert meta_out.agent_status == "cost_capped"
    # token_usage was populated.
    assert meta_out.token_usage and meta_out.token_usage > 0


# --- SC-6 ----------------------------------------------------------------

def test_sc6_agent_never_authors_markdown():
    """SC-6: AgentScanReport has no markdown-shaped field."""
    from repo_audit.agent.schema import (
        AgentScanReport, DimensionNarrative, SeverityCall,
    )

    forbidden_fields = {"markdown", "md", "html", "text_markdown",
                        "raw_md", "rendered"}
    for model in (AgentScanReport, DimensionNarrative, SeverityCall):
        leaked = forbidden_fields & set(model.model_fields.keys())
        assert not leaked, (
            f"SC-6: {model.__name__} has markdown-shaped field(s): {leaked}"
        )
