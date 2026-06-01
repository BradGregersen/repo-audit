"""Contract tests for the generic SARIF 2.1.0 -> Finding parser (FND-01).

sarif_to_findings(sarif_dict, *, source_tool, default_dimension, severity_map)
    -> list[Finding]

These pin:
- round-trip of a minimal 1-result SARIF doc (file/line/rule_id/source_tool/message)
- critical+static auto-caveat (D-06-02) fires BEFORE construction
- the would-raise documentation test (WHY the auto-caveat path exists)
- source_tool tagged on every Finding (BYO-01 traceability)
- sparse-but-well-formed docs never raise (default_dimension fallback, info floor)
- multiple runs x results flattened
- invalid default_dimension rejected loudly at call entry
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from repo_audit.adapters.sarif import sarif_to_findings
from repo_audit.schema.finding import Finding


def _sarif(results, *, rules=None):
    """Build a 1-run SARIF doc around the given results list."""
    driver: dict = {"name": "test-tool"}
    if rules is not None:
        driver["rules"] = rules
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
            }
        ],
    }


def _result(*, rule_id="RULE001", level="warning", message="something happened",
            uri="src/app.ts", start_line=42):
    res: dict = {}
    if rule_id is not None:
        res["ruleId"] = rule_id
    if level is not None:
        res["level"] = level
    if message is not None:
        res["message"] = {"text": message}
    if uri is not None:
        res["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line} if start_line is not None else {},
                }
            }
        ]
    return res


class TestRoundTrip:
    def test_round_trip_minimal_sarif(self):
        doc = _sarif([_result()])
        findings = sarif_to_findings(
            doc, source_tool="test-tool", default_dimension="security", severity_map={}
        )
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.file == "src/app.ts"
        assert f.line == 42
        assert f.rule_id == "RULE001"
        assert f.source_tool == "test-tool"
        assert f.evidence.output_snippet == "something happened"
        assert f.evidence.tool == "test-tool"
        assert f.evidence.parsed_value["rule_id"] == "RULE001"
        assert f.evidence.parsed_value["sarif_level"] == "warning"
        assert f.evidence.line_range == (42, 42)
        assert f.evidence_type == "static"
        assert f.confidence == "candidate"
        assert f.dimension == "security"
        assert f.severity == "major"  # warning -> major

    def test_rule_id_falls_back_to_nested_rule_id(self):
        res = _result(rule_id=None)
        res["rule"] = {"id": "NESTED-1"}
        findings = sarif_to_findings(
            _sarif([res]), source_tool="t", default_dimension="security", severity_map={}
        )
        assert findings[0].rule_id == "NESTED-1"


class TestCriticalStaticAutoCaveat:
    def test_critical_static_gets_auto_caveat(self):
        # level=error -> critical; static + candidate would be invalid WITHOUT a caveat.
        findings = sarif_to_findings(
            _sarif([_result(level="error")]),
            source_tool="osv-scanner",
            default_dimension="security",
            severity_map={},
        )
        f = findings[0]
        assert f.severity == "critical"
        assert f.confidence_caveat is not None
        assert f.confidence_caveat.strip() != ""
        # source_tool should be threaded into the caveat for traceability.
        assert "osv-scanner" in f.confidence_caveat

    def test_candidate_critical_without_caveat_would_raise(self):
        # Documents WHY the auto-caveat path exists: this construction is illegal.
        with pytest.raises((ValidationError, ValueError)):
            Finding(
                dimension="security",
                severity="critical",
                evidence_type="static",
                confidence="candidate",
                confidence_caveat=None,
                evidence={"tool": "x"},
            )


class TestSourceToolTagging:
    def test_source_tool_tagged_on_every_finding(self):
        doc = _sarif([_result(rule_id="A"), _result(rule_id="B", level="note")])
        findings = sarif_to_findings(
            doc, source_tool="my-tool", default_dimension="quality", severity_map={}
        )
        assert len(findings) == 2
        assert all(f.source_tool == "my-tool" for f in findings)
        assert all(f.evidence.tool == "my-tool" for f in findings)


class TestSparseDoc:
    def test_sparse_result_uses_default_dimension_and_does_not_raise(self):
        # no level, no locations, no ruleId
        doc = _sarif([{"message": {}}])
        findings = sarif_to_findings(
            doc, source_tool="t", default_dimension="architecture_rot", severity_map={}
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.dimension == "architecture_rot"
        assert f.severity == "info"  # missing level floors at info
        assert f.file is None
        assert f.line is None
        assert f.rule_id == ""
        assert f.evidence.output_snippet == ""
        assert f.evidence.line_range is None

    def test_empty_runs_yields_no_findings(self):
        assert sarif_to_findings(
            {"runs": []}, source_tool="t", default_dimension="security", severity_map={}
        ) == []

    def test_missing_runs_key_yields_no_findings(self):
        assert sarif_to_findings(
            {}, source_tool="t", default_dimension="security", severity_map={}
        ) == []


class TestFlattening:
    def test_multiple_runs_and_results_flattened(self):
        run = {
            "tool": {"driver": {"name": "t"}},
            "results": [_result(rule_id="A"), _result(rule_id="B")],
        }
        doc = {"version": "2.1.0", "runs": [run, dict(run)]}
        findings = sarif_to_findings(
            doc, source_tool="t", default_dimension="security", severity_map={}
        )
        assert len(findings) == 4


class TestSecuritySeverityLookup:
    def test_security_severity_from_rule_properties_overrides_level(self):
        rules = [{"id": "RULE001", "properties": {"security-severity": "9.5"}}]
        doc = _sarif([_result(level="warning")], rules=rules)
        findings = sarif_to_findings(
            doc, source_tool="t", default_dimension="security", severity_map={}
        )
        f = findings[0]
        assert f.severity == "critical"  # band 9.5 wins over warning
        assert f.confidence_caveat  # critical+static auto-caveat present
        assert f.evidence.parsed_value["security_severity"] == "9.5"

    def test_security_severity_from_result_properties_used_when_no_rule(self):
        res = _result(level="note")
        res["properties"] = {"security-severity": "8.0"}
        findings = sarif_to_findings(
            _sarif([res]), source_tool="t", default_dimension="security", severity_map={}
        )
        assert findings[0].severity == "major"  # 8.0 band -> major


class TestInvalidDimension:
    def test_invalid_default_dimension_rejected(self):
        with pytest.raises(ValueError):
            sarif_to_findings(
                _sarif([_result()]),
                source_tool="t",
                default_dimension="bogus",
                severity_map={},
            )

    def test_invalid_default_dimension_rejected_even_with_empty_doc(self):
        # Fail loud at call entry — mis-config caught before any parsing.
        with pytest.raises(ValueError):
            sarif_to_findings(
                {"runs": []},
                source_tool="t",
                default_dimension="not-a-dimension",
                severity_map={},
            )
