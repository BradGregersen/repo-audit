"""VER-03 — critic must cite file:line / lockfile / policy / sibling_ref; an
uncited/invalid refutation is discarded (logged, no retry, zero effect).

Plan 17-02 Task 2 implements the deterministic citation validator + the
submit_verdict / get_repo_excerpt MCP boundary tools + the read-only options
builder. The LLM is advisory; Python (`_citation_is_valid`) is authoritative.
"""
from __future__ import annotations

import asyncio
import json

from repo_audit.verification.critic import (
    _citation_is_valid,
    build_critic_options,
    build_critic_mcp_server,
    get_discarded,
    get_repo_excerpt,
    get_submitted_verdict,
    reset_critic_state,
    submit_verdict,
)
from repo_audit.verification.record import Citation, build_finding_ref


# --- _citation_is_valid: file_line --------------------------------------


def test_file_line_citation_resolves_true(fake_repo_with_source):
    """An existing file + an in-range line validates True."""
    cite = Citation(kind="file_line", file="src/app/auth.py", line=1)
    assert _citation_is_valid(cite, fake_repo_with_source, []) is True


def test_file_line_past_eof_is_false_not_exception(fake_repo_with_source):
    """A line past EOF returns False (never raises)."""
    cite = Citation(kind="file_line", file="src/app/auth.py", line=9999)
    assert _citation_is_valid(cite, fake_repo_with_source, []) is False


def test_file_line_missing_file_is_false(fake_repo_with_source):
    """A missing file returns False (never raises)."""
    cite = Citation(kind="file_line", file="src/app/nope.py", line=1)
    assert _citation_is_valid(cite, fake_repo_with_source, []) is False


# --- _citation_is_valid: sibling_ref ------------------------------------


def test_sibling_ref_validates_true_when_in_set(fake_finding):
    """A sibling_ref matching a fingerprint in the current finding set → True."""
    sibling = fake_finding(file="src/a.py", line=3, rule_id="DUP-1")
    ref = build_finding_ref(sibling)
    cite = Citation(kind="sibling_ref", sibling_finding_ref=ref)
    assert _citation_is_valid(cite, None, [sibling]) is True


def test_sibling_ref_validates_false_when_not_in_set(fake_finding):
    """A sibling_ref with NO match in the finding set → False."""
    sibling = fake_finding(file="src/a.py", line=3, rule_id="DUP-1")
    cite = Citation(kind="sibling_ref", sibling_finding_ref="ghost::X::y.py:9")
    assert _citation_is_valid(cite, None, [sibling]) is False


# --- submit_verdict handler: cite-or-discarded, no retry ----------------


def _invoke(payload: dict, *, repo_path, finding_set):
    """Drive the submit_verdict handler once with critic-context wiring."""
    reset_critic_state(repo_path=repo_path, finding_set=finding_set)
    return asyncio.run(submit_verdict.handler(payload))


def test_uncited_refutation_discarded_no_retry(fake_repo_with_source, fake_finding):
    """An uncited/invalid refutation is discarded — logged, no retry, zero effect.

    VER-03 / D-17-15: the handler records a discarded RefutationRecord
    (citation_valid=False), returns INERT (no is_error repair retry), and stores
    NO surviving verdict — the finding stays at its deterministic rung. A real
    file:line citation, by contrast, validates True and is applied.
    """
    candidate = fake_finding(file="src/app/auth.py", line=1)

    # 1) A refutation pointing past EOF (invalid citation) is discarded.
    bad = {
        "outcome": "refuted",
        "angle": "static_read_as_runtime",
        "citation": {"kind": "file_line", "file": "src/app/auth.py", "line": 9999},
        "reason": "claims runtime path that does not exist",
    }
    result = _invoke(bad, repo_path=fake_repo_with_source, finding_set=[candidate])
    # Inert: NOT an is_error repair retry (unlike emit_report).
    assert result.get("is_error") is not True
    # The refutation was discarded, not applied.
    assert get_submitted_verdict() is None
    discarded = get_discarded()
    assert len(discarded) == 1
    assert discarded[0].citation_valid is False

    # 2) A refutation with a REAL, in-range file:line citation validates + applies.
    good = {
        "outcome": "refuted",
        "angle": "upstream_guard",
        "citation": {"kind": "file_line", "file": "src/app/auth.py", "line": 1},
        "reason": "guarded upstream at auth.py:1",
    }
    result2 = _invoke(good, repo_path=fake_repo_with_source, finding_set=[candidate])
    verdict = get_submitted_verdict()
    assert verdict is not None
    assert verdict.refutation is not None
    assert verdict.refutation.citation_valid is True
    assert not get_discarded()  # state reset per candidate; no discard this time


def test_survived_verdict_stores_no_refutation(fake_repo_with_source, fake_finding):
    """outcome='survived' stores a survive verdict with no refutation."""
    candidate = fake_finding()
    payload = {"outcome": "survived", "angle": None, "citation": None, "reason": "stands"}
    _invoke(payload, repo_path=fake_repo_with_source, finding_set=[candidate])
    verdict = get_submitted_verdict()
    assert verdict is not None
    assert verdict.refutation is None
    assert not get_discarded()


def test_duplicate_angle_sibling_ref_applies(fake_repo_with_source, fake_finding):
    """A duplicate-angle refutation citing a sibling fingerprint in the set applies."""
    candidate = fake_finding(file="src/app/auth.py", line=1, rule_id="A")
    sibling = fake_finding(file="src/app/auth.py", line=1, rule_id="B", source_tool="other")
    ref = build_finding_ref(sibling)
    payload = {
        "outcome": "refuted",
        "angle": "duplicate",
        "citation": {"kind": "sibling_ref", "sibling_finding_ref": ref},
        "reason": "dup of sibling",
    }
    _invoke(payload, repo_path=fake_repo_with_source, finding_set=[candidate, sibling])
    verdict = get_submitted_verdict()
    assert verdict is not None and verdict.refutation is not None
    assert verdict.refutation.citation_valid is True
    assert verdict.refutation.angle == "duplicate"


# --- get_repo_excerpt: read-only, never raises --------------------------


def test_get_repo_excerpt_returns_bounded_text(fake_repo_with_source):
    reset_critic_state(repo_path=fake_repo_with_source, finding_set=[])
    result = asyncio.run(
        get_repo_excerpt.handler({"file": "src/app/auth.py", "line_range": [1, 2]})
    )
    text = result["content"][0]["text"]
    assert "token_hex" in text
    assert result.get("is_error") is not True


def test_get_repo_excerpt_missing_file_is_inert(fake_repo_with_source):
    reset_critic_state(repo_path=fake_repo_with_source, finding_set=[])
    result = asyncio.run(
        get_repo_excerpt.handler({"file": "nope/missing.py", "line_range": [1, 2]})
    )
    # Never raises; returns a "not found" payload.
    assert result is not None
    assert "content" in result


# --- build_critic_options: provably read-only on the target repo --------


def test_build_critic_options_is_read_only():
    """tools=[] AND allowed_tools whitelists ONLY the two read-only MCP tools."""
    server = build_critic_mcp_server()
    opts = build_critic_options(mcp_server=server, system_prompt="x")
    assert opts.tools == []
    assert opts.allowed_tools == [
        "mcp__critic__submit_verdict",
        "mcp__critic__get_repo_excerpt",
    ]
    forbidden = ("Write", "Bash", "Read", "Edit", "WebSearch", "WebFetch")
    for bad in forbidden:
        assert bad not in opts.allowed_tools
    assert opts.permission_mode == "bypassPermissions"


def test_submit_verdict_input_schema_is_verdict_payload():
    """The submit_verdict tool advertises the VerdictPayload schema (extra=forbid)."""
    schema = submit_verdict.input_schema
    schema_json = json.dumps(schema)
    assert "outcome" in schema_json
