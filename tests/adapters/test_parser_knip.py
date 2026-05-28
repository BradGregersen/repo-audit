"""Phase 3 Wave 2 contract — SKIP via importorskip until plan 03-04 lands."""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.knip",
    reason="Wave 2 (plan 03-04) not yet landed — parsers.knip missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript.parsers.knip import parse  # noqa: E402


def test_clean_returns_empty(recorded_tool_output):
    stdout, stderr, rc = recorded_tool_output("knip", "clean")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []


def test_candidate_info_enforcement(recorded_tool_output):
    """D-50 / SAFE-05: every knip Finding is ``confidence='candidate'`` AND ``severity='info'``.

    The parser caps at info via ``_KNIP_SEVERITY = "info"`` constant
    (parser-internal — NOT SCH-04). The widened SCH-04 (Decision B) permits
    major-at-candidate, so this is the parser's own structural guard.
    """
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert len(findings) >= 1
    for f in findings:
        assert f.confidence == "candidate"
        assert f.severity == "info"


def test_recommendation_says_verify_not_delete(recorded_tool_output):
    """SAFE-05: recommendation text MUST say ``verify`` (not ``delete``) below confirmed."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    for f in findings:
        rec = (f.recommendation or "").lower()
        assert "delete" not in rec
        assert "verify" in rec or "investigate" in rec or "review" in rec


def test_unused_export_emits_finding(recorded_tool_output):
    """Per-file ``exports`` entries ⇒ one Finding per export name."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    export_findings = [f for f in findings if "deadFn" in (f.title or "")
                       or "deadFn" in (f.evidence.snippet or "")]
    assert len(export_findings) >= 1


def test_unused_dependency_emits_finding(recorded_tool_output):
    """``dependencies`` entries ⇒ one Finding per unused dep (lodash in fixture)."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    dep_findings = [f for f in findings if "lodash" in (f.title or "")
                    or "lodash" in (f.evidence.snippet or "")]
    assert len(dep_findings) >= 1


def test_malformed_json_returns_empty(recorded_tool_output):
    """Truncated JSON ⇒ parser returns ``[]``."""
    stdout, stderr, rc = recorded_tool_output("knip", "malformed")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []
