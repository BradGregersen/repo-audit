"""tsc parser contract tests.

The opening ``pytest.importorskip`` guards the parser module, so this file skips
cleanly in a build where that module is not present and runs in full where it is.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.tsc",
    reason="optional module repo_audit.adapters.typescript.parsers.tsc not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript.parsers import tsc as tsc_parser  # noqa: E402
from repo_audit.adapters.typescript.parsers.tsc import parse  # noqa: E402


def test_clean_returns_empty(recorded_tool_output):
    """tsc with no diagnostics ⇒ empty Finding list."""
    stdout, stderr, rc = recorded_tool_output("tsc", "clean")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []


def test_errors_returns_three_findings(recorded_tool_output):
    """The errors fixture has 3 diagnostic lines ⇒ 3 Findings."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert len(findings) == 3


def test_finding_dimension_is_correctness(recorded_tool_output):
    """D-48: tsc Findings live in the correctness dimension."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        assert f.dimension == "correctness"


def test_finding_severity_is_critical(recorded_tool_output):
    """D-51: every tsc Finding is severity='critical'."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        assert f.severity == "critical"


def test_finding_evidence_type_is_static(recorded_tool_output):
    """D-17: tsc Findings are static-analysis evidence."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        assert f.evidence_type == "static"


def test_all_findings_have_caveat(recorded_tool_output):
    """D-51 / SCH-03: critical+static Findings MUST carry a non-empty caveat."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        assert f.confidence_caveat is not None
        assert f.confidence_caveat.strip() != ""


def test_rule_id_is_ts_code(recorded_tool_output):
    """The errors fixture's diagnostics are TS2322, TS2532, TS2304."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert [f.rule_id for f in findings] == ["TS2322", "TS2532", "TS2304"]


def test_file_path_extracted(recorded_tool_output):
    """File path is captured verbatim from the diagnostic prefix."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert [f.file for f in findings] == ["src/foo.ts", "src/foo.ts", "src/bar.ts"]


def test_line_number_extracted(recorded_tool_output):
    """Line numbers come straight from the diagnostic."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert [f.line for f in findings] == [12, 18, 3]


def test_evidence_parsed_value_contains_keys(recorded_tool_output):
    """parsed_value carries diagnostic_code, column, message."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        pv = f.evidence.parsed_value
        assert set(pv.keys()) >= {"diagnostic_code", "column", "message"}
        assert pv["diagnostic_code"].startswith("TS")
        assert isinstance(pv["column"], int)
        assert isinstance(pv["message"], str) and pv["message"]


def test_non_matching_lines_skipped():
    """Non-diagnostic lines are silently ignored (no raise)."""
    inv = InvocationResult(
        stdout="some progress\nFound 3 errors in 2 files.\n",
        stderr="",
        returncode=0,
    )
    assert parse(inv) == []


def test_mixed_input_only_matches_diagnostics(recorded_tool_output):
    """Garbage lines mixed with diagnostics ⇒ only diagnostics counted."""
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    mixed = stdout + "\nFound 3 errors.\nsome other progress noise\n"
    findings = parse(InvocationResult(stdout=mixed, stderr=stderr, returncode=rc))
    assert len(findings) == 3


def test_sch03_validator_would_raise_without_caveat(
    recorded_tool_output, monkeypatch
):
    """SCH-03 structural guard: empty caveat ⇒ ValidationError on construction.

    Monkey-patches ``TSC_DEFAULT_CAVEAT`` to an empty string and asserts that
    parsing the errors fixture now raises. Proves the Finding-level validator
    is the structural enforcement, not a parser-side check.
    """
    monkeypatch.setattr(tsc_parser, "TSC_DEFAULT_CAVEAT", "")
    stdout, stderr, rc = recorded_tool_output("tsc", "errors")
    with pytest.raises(ValueError, match="SAFE-01"):
        parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
