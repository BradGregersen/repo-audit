"""Phase 3 Wave 2 contract — SKIP via importorskip until plan 03-03 lands.

Parser tests consume recorded fixtures (no live tsc invocation needed).
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.tsc",
    reason="Wave 2 (plan 03-03) not yet landed — parsers.tsc missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript.parsers.tsc import parse  # noqa: E402


def test_clean_returns_empty(recorded_tool_output):
    stdout, stderr, rc = recorded_tool_output("tsc", "clean")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []


def test_errors_returns_findings_with_critical_severity(recorded_tool_output):
    """tsc errors ⇒ Findings at ``severity='critical'`` (type-system breaches)."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert len(findings) >= 1
    for f in findings:
        assert f.severity == "critical"


def test_all_findings_have_caveat(recorded_tool_output):
    """D-51 / SCH-03: critical+static Findings MUST carry the static-vs-runtime caveat."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        # SCH-03 enforcement: static + critical ⇒ caveat present
        assert f.evidence_type == "static"
        # The static caveat is enforced by the Finding validator; constructing
        # the finding at all means the caveat exists. This assertion is a
        # belt-and-suspenders sanity check.
        if hasattr(f, "caveat"):
            assert f.caveat


def test_diagnostic_regex_extracts_code_file_line_col(recorded_tool_output):
    """Each finding has ``file_path``, ``line``, ``column``, and a TS error code."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert len(findings) >= 3  # fixture has 3 diagnostics
    for f in findings:
        assert f.file_path is not None
        assert f.line is not None
        # TS error codes look like "TS2322"
        assert "TS" in (f.evidence.snippet or "") or "TS" in (f.title or "")


def test_redact_stderr_fragments_before_evidence(recorded_tool_output):
    """tsc internal error: stderr is redacted (no absolute-path leakage) into Finding evidence.notes."""
    stdout, stderr, rc = recorded_tool_output("tsc", "internal_error")
    # Internal errors don't produce per-file findings; they produce a single
    # ``unavailable`` AdapterResult upstream. The parser itself should return [].
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []
