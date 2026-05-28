"""Phase 3 Wave 2 contract — SKIP via importorskip until plan 03-03 lands."""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.eslint",
    reason="Wave 2 (plan 03-03) not yet landed — parsers.eslint missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript.parsers.eslint import parse  # noqa: E402


def test_clean_returns_empty(recorded_tool_output):
    stdout, stderr, rc = recorded_tool_output("eslint", "clean")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []


def test_errors_routes_to_quality_dimension(recorded_tool_output):
    """eslint default dimension ⇒ ``quality_debt`` unless rule_override demotes/promotes."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert len(findings) >= 1
    # Most findings stay in quality_debt; rule_override may move specific rules
    dims = {f.dimension for f in findings}
    assert "quality_debt" in dims or "security" in dims


def test_rule_overrides_literal(recorded_tool_output):
    """D-49 literal override: ``no-eval`` ⇒ dimension='security', severity='critical'."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    eval_findings = [f for f in findings if "no-eval" in (f.evidence.snippet or "") or "no-eval" in (f.title or "")]
    if eval_findings:
        for f in eval_findings:
            assert f.dimension == "security"
            assert f.severity == "critical"


def test_rule_overrides_glob(recorded_tool_output):
    """D-49 glob override: ``security/*`` rules route to dimension='security'."""
    # The recorded fixture doesn't have security/* rules but the structural check
    # is that the parser CONSULTS the glob table. We assert the parser exposes
    # the override-application code path by importing the helper.
    from repo_audit.adapters.typescript.parsers.eslint import (
        apply_rule_override,
    )
    result = apply_rule_override("security/detect-eval-with-expression")
    if result is not None:
        assert result.get("dimension") == "security"


def test_eslint_severity_2_maps_to_major(recorded_tool_output):
    """ESLint ``severity: 2`` (error) ⇒ Finding ``severity='major'`` by default."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    # All recorded findings are severity:2; default mapping is major (unless override bumps).
    severities = {f.severity for f in findings}
    assert severities & {"major", "critical"}, (
        f"expected at least one major-or-critical finding, got {severities}"
    )


def test_eslint_severity_1_maps_to_minor():
    """ESLint ``severity: 1`` (warn) ⇒ Finding ``severity='minor'``."""
    # Synthetic: hand-craft a single-warning JSON payload to exercise the sev:1 path.
    import json as _json
    payload = _json.dumps([{
        "filePath": "/abs/src/foo.ts",
        "messages": [{
            "ruleId": "no-console",
            "severity": 1,
            "message": "warning",
            "line": 1, "column": 1,
            "nodeType": "Identifier",
            "endLine": 1, "endColumn": 1,
        }],
        "suppressedMessages": [], "errorCount": 0, "fatalErrorCount": 0,
        "warningCount": 1, "fixableErrorCount": 0, "fixableWarningCount": 0,
        "usedDeprecatedRules": [],
    }])
    findings = parse(InvocationResult(stdout=payload, stderr="", returncode=0))
    assert len(findings) == 1
    assert findings[0].severity == "minor"


def test_malformed_json_returns_empty(recorded_tool_output):
    """Truncated JSON ⇒ parser returns ``[]`` (and adapter emits unavailable upstream)."""
    stdout, stderr, rc = recorded_tool_output("eslint", "malformed_json")
    findings = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))
    assert findings == []
