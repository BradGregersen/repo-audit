"""Pin the partial-scan qualify-scope guidance in the D-56 system prompt.

Quick task 260530-bj8: a partial scan is the COMMON case (one oversized /
binary / skipped file or one unavailable collector flips meta.partial). The
narrator's Section-8 instruction must steer it away from the three standalone
tokens that completion_honesty._FORBIDDEN_RE forbids, otherwise the pre-write
completion-honesty gate HARD-REFUSES the whole report (exit 3, no report).

These tests render the prompt via build_options (the real boot path) for
partial=True and partial=False and assert:
  1. the partial prompt carries the qualify-scope guidance, names the exit-3
     hard-refuse consequence, and enumerates EACH forbidden token — and
     cross-checks that token set against the linter so a future linter edit
     fails here until the prompt is updated to match;
  2. the full-scan prompt omits the qualify-scope block, and the two prompts
     differ (the block is conditioned on `partial`).
"""
from __future__ import annotations

import re
from datetime import date

import pytest

pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")


def _build_prompt(tmp_path, *, partial: bool) -> str:
    """Render options.system_prompt via the real build_options boot path."""
    import repo_audit.adapters.typescript as _ts  # noqa: F401 — register adapter
    from repo_audit.agent.options import build_options
    from repo_audit.agent.tools import (
        available_tools_for_prompt,
        build_mcp_server,
    )
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
        partial=partial,
        mcp_server=server,
        available_tools_for_prompt=available_tools_for_prompt(),
    )
    return options.system_prompt


def _forbidden_tokens() -> list[str]:
    """Pull the literal alternatives out of completion_honesty._FORBIDDEN_RE.

    Cross-checking against the live linter regex means a future change to its
    token set fails these tests until the prompt enumerates the new set too.
    """
    from repo_audit.render.completion_honesty import _FORBIDDEN_RE

    # Pattern is r"\b(all|every|complete)\b" — capture the (...) group body.
    m = re.search(r"\(([^)]+)\)", _FORBIDDEN_RE.pattern)
    assert m is not None, "could not parse _FORBIDDEN_RE alternatives"
    tokens = [t.strip().lower() for t in m.group(1).split("|")]
    assert tokens, "no forbidden tokens parsed from _FORBIDDEN_RE"
    return tokens


def test_partial_prompt_enumerates_forbidden_tokens_and_qualifies_scope(tmp_path):
    """Partial prompt: qualify-scope guidance + exit-3 consequence + every token."""
    prompt = _build_prompt(tmp_path, partial=True).lower()

    # Qualify-scope guidance present.
    assert "in-scope" in prompt, "partial prompt must steer to 'in-scope' phrasing"

    # The real hard-refuse consequence (not the stale 'strip the sentence' wording).
    assert any(word in prompt for word in ("exit", "refuse", "abort")), (
        "partial prompt must state the exit-3 hard-refuse consequence"
    )

    # Every linter token is enumerated — cross-checked against the live regex so
    # a future _FORBIDDEN_RE edit fails until the prompt is updated to match.
    for token in _forbidden_tokens():
        assert token in prompt, (
            f"partial prompt must enumerate forbidden token {token!r} "
            f"(mirrors completion_honesty._FORBIDDEN_RE)"
        )


def test_full_scan_prompt_omits_qualify_scope_block(tmp_path):
    """Full scan: no qualify-scope block, and the prompt differs from partial."""
    partial_prompt = _build_prompt(tmp_path, partial=True)
    full_prompt = _build_prompt(tmp_path, partial=False)

    assert "in-scope" not in full_prompt.lower(), (
        "full-scan prompt must NOT carry the qualify-scope block"
    )
    assert partial_prompt != full_prompt, (
        "the qualify-scope block must be conditioned on `partial`"
    )
