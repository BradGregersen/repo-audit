"""Phase 3 Wave 2 (plan 03-04): eslint parser contract tests.

Replaces Wave 0b scaffolding (the previous test bodies were authored
against a Finding-schema shape that does not match the current Phase-1
schema — fields like ``title``, ``evidence.snippet`` do not exist; the
old ``apply_rule_override`` helper is not part of the plan-spec API).
Plan 03-04 instructs the executor to implement these tests as the
contract for the eslint parser.

The opening ``pytest.importorskip`` line is retained so the module SKIPS
cleanly when the parser is absent and flips ACTIVE once the symbol lands
(per plan 03-01b Warning-8 pattern). Once the parser module ships, the
importorskip is a no-op and these tests run.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.eslint",
    reason="Wave 2 (plan 03-04) not yet landed — parsers.eslint missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript import (  # noqa: E402
    CONFIG as TS_CONFIG,
)
from repo_audit.adapters.typescript.parsers import (  # noqa: E402
    eslint as eslint_parser,
)
from repo_audit.adapters.typescript.parsers.eslint import (  # noqa: E402
    parse,
)


def test_clean_returns_empty(recorded_tool_output):
    """eslint with no diagnostics (``[]`` JSON) ⇒ empty Finding list."""
    stdout, stderr, rc = recorded_tool_output("eslint", "clean")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert findings == []


def test_errors_returns_two_findings(recorded_tool_output):
    """The errors fixture has 1 file × 2 messages ⇒ exactly 2 Findings."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert len(findings) == 2


def test_rule_overrides_literal_no_eval_to_security_critical(
    recorded_tool_output,
):
    """D-49 literal override: ``no-eval`` ⇒ security/critical + caveat from YAML."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    eval_findings = [f for f in findings if f.rule_id == "no-eval"]
    assert len(eval_findings) == 1
    f = eval_findings[0]
    assert f.dimension == "security"
    assert f.severity == "critical"
    assert f.confidence_caveat is not None
    assert f.confidence_caveat.strip() != ""


def test_default_routing_no_undef_to_quality_major(recorded_tool_output):
    """No override matches ``no-undef`` ⇒ default dimension='quality', severity='major'."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    no_undef = [f for f in findings if f.rule_id == "no-undef"]
    assert len(no_undef) == 1
    f = no_undef[0]
    assert f.dimension == "quality"
    assert f.severity == "major"


def test_eslint_severity_2_maps_to_major():
    """eslint severity int 2 (error) with no override ⇒ severity='major'."""
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "no-console",
                        "severity": 2,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    assert findings[0].severity == "major"


def test_eslint_severity_1_maps_to_minor():
    """eslint severity int 1 (warning) with no override ⇒ severity='minor'."""
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "no-console",
                        "severity": 1,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    assert findings[0].severity == "minor"


def test_rule_overrides_glob_security_star():
    """D-49 glob ``security/*`` ⇒ dimension='security', severity='major'."""
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "security/detect-buffer-noassert",
                        "severity": 2,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    f = findings[0]
    assert f.dimension == "security"
    assert f.severity == "major"


def test_rule_overrides_glob_floating_promises():
    """D-49 glob ``@typescript-eslint/no-floating-promises`` raises minor to major."""
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "@typescript-eslint/no-floating-promises",
                        # eslint reports this as severity 1 (warn) by default in
                        # the recommended config; the glob override should
                        # raise it.
                        "severity": 1,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    f = findings[0]
    assert f.dimension == "correctness"
    assert f.severity == "major"


def test_malformed_json_returns_empty(recorded_tool_output):
    """Truncated JSON ⇒ parser returns []; adapter handles status='unavailable'."""
    stdout, stderr, rc = recorded_tool_output("eslint", "malformed_json")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert findings == []


def test_non_list_json_returns_empty():
    """A JSON object (not the expected top-level array) ⇒ []."""
    findings = parse(InvocationResult(stdout='{"oops": "object_not_list"}'))
    assert findings == []


def test_evidence_parsed_value_keys(recorded_tool_output):
    """parsed_value carries the rule_id/column/severity_int triple."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    for f in findings:
        pv = f.evidence.parsed_value
        assert set(pv.keys()) >= {"rule_id", "column", "severity_int"}


def test_critical_override_without_yaml_caveat_uses_fallback(monkeypatch):
    """SCH-03 fallback: critical promotion without YAML caveat ⇒ parser supplies
    ``_FALLBACK_CRITICAL_CAVEAT``.

    Monkey-patches the live CONFIG dict to inject a synthetic override
    that omits ``confidence_caveat``. The parser MUST still construct
    the Finding by filling in the fallback string. Proves SCH-03 cannot
    fire on critical+static even when YAML drops a caveat.

    NOTE (Warning 11): the patch targets the CONFIG dict that the parser
    re-reads at call time via ``_current_overrides``. If the parser had
    snapshotted overrides at module load, this test would fail because
    the synthetic rule wouldn't be visible.
    """
    overrides = dict(TS_CONFIG["tools"]["eslint"].get("rule_overrides") or {})
    overrides["synthetic-rule"] = {
        "dimension": "security",
        "severity": "critical",
        # NB: no confidence_caveat key — exercises the fallback path.
    }
    monkeypatch.setitem(
        TS_CONFIG["tools"]["eslint"], "rule_overrides", overrides
    )
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "synthetic-rule",
                        "severity": 2,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    assert (
        findings[0].confidence_caveat
        == eslint_parser._FALLBACK_CRITICAL_CAVEAT
    )


def test_overrides_resolved_at_call_time_not_module_load(monkeypatch):
    """Warning 11 structural guard: late-injected overrides MUST be honored.

    The parser must NOT close over a module-load-time snapshot of CONFIG.
    Inject a NEW rule_overrides entry AFTER the parser is already
    imported and assert the parser sees it on the next call.
    """
    overrides = dict(TS_CONFIG["tools"]["eslint"].get("rule_overrides") or {})
    overrides["late-injected-rule"] = {
        "dimension": "architecture_rot",
        "severity": "minor",
    }
    monkeypatch.setitem(
        TS_CONFIG["tools"]["eslint"], "rule_overrides", overrides
    )
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "late-injected-rule",
                        "severity": 2,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert len(findings) == 1
    f = findings[0]
    assert f.dimension == "architecture_rot"
    # The override pins severity='minor' (not the eslint-int 2 → 'major' default).
    assert f.severity == "minor"


def test_zero_severity_skipped():
    """severity=0 (suppressed) should not appear in messages[], but defensively skip."""
    payload = json.dumps(
        [
            {
                "filePath": "/x.ts",
                "messages": [
                    {
                        "ruleId": "no-console",
                        "severity": 0,
                        "message": "x",
                        "line": 1,
                        "column": 1,
                    }
                ],
            }
        ]
    )
    findings = parse(InvocationResult(stdout=payload))
    assert findings == []


def test_file_path_extracted(recorded_tool_output):
    """Finding.file mirrors the eslint entry's filePath."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert {f.file for f in findings} == {"/abs/src/foo.ts"}


def test_line_extracted(recorded_tool_output):
    """Finding.line mirrors the eslint message's line."""
    stdout, stderr, rc = recorded_tool_output("eslint", "errors")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    lines_by_rule = {f.rule_id: f.line for f in findings}
    assert lines_by_rule == {"no-undef": 1, "no-eval": 4}
