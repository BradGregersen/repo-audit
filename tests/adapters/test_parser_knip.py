"""Phase 3 Wave 2 (plan 03-04): knip parser contract tests.

Replaces Wave 0b scaffolding (the previous test bodies were authored
against a Finding-schema shape that does not match the current Phase-1
schema — fields like ``title`` and ``evidence.snippet`` do not exist).
Plan 03-04 instructs the executor to implement these tests as the
contract for the knip parser.

The opening ``pytest.importorskip`` line is retained so the module SKIPS
cleanly when the parser is absent and flips ACTIVE once the symbol lands
(per plan 03-01b Warning-8 pattern). Once the parser module ships, the
importorskip is a no-op and these tests run.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.knip",
    reason="Wave 2 (plan 03-04) not yet landed — parsers.knip missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.typescript.parsers import (  # noqa: E402
    knip as knip_parser,
)
from repo_audit.adapters.typescript.parsers.knip import (  # noqa: E402
    _CATEGORY_LABELS,
    parse,
)


def test_clean_returns_empty(recorded_tool_output):
    """knip with no issues (``{"issues": []}``) ⇒ empty Finding list."""
    stdout, stderr, rc = recorded_tool_output("knip", "clean")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert findings == []


def test_issues_returns_three_findings(recorded_tool_output):
    """The issues fixture has 1 dep + 1 export + 1 file ⇒ exactly 3 Findings."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert len(findings) == 3


def test_every_finding_is_candidate_info_architecture_rot(
    recorded_tool_output,
):
    """D-50 / SAFE-05: every knip Finding lands at candidate/info/architecture_rot."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert findings, "fixture should produce at least one Finding"
    for f in findings:
        assert f.confidence == "candidate"
        assert f.severity == "info"
        assert f.dimension == "architecture_rot"


def test_every_finding_recommendation_contains_verify(recorded_tool_output):
    """SAFE-05: recommendation MUST say 'verify with grep' on every Finding."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    for f in findings:
        assert "verify with grep" in (f.recommendation or "")


def test_no_finding_recommendation_says_delete(recorded_tool_output):
    """SAFE-05 phrasing: never use the word 'delete' below confirmed rung."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    for f in findings:
        rec = (f.recommendation or "").lower()
        assert "delete" not in rec


def test_rule_ids_are_category_labels(recorded_tool_output):
    """Every Finding's rule_id is one of the _CATEGORY_LABELS values."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    label_values = set(_CATEGORY_LABELS.values())
    for f in findings:
        assert f.rule_id in label_values


def test_unused_dependency_finding_present(recorded_tool_output):
    """Fixture has lodash as unused dependency on package.json."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    deps = [f for f in findings if f.rule_id == "unused_dependency"]
    assert len(deps) == 1
    f = deps[0]
    assert f.evidence.parsed_value["symbol_name"] == "lodash"
    assert f.file == "package.json"


def test_unused_export_finding_present(recorded_tool_output):
    """Fixture has deadFn as unused export on src/dead.ts line 5."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    exports = [f for f in findings if f.rule_id == "unused_export"]
    assert len(exports) == 1
    f = exports[0]
    assert f.evidence.parsed_value["symbol_name"] == "deadFn"
    assert f.file == "src/dead.ts"
    assert f.line == 5


def test_unused_file_finding_present(recorded_tool_output):
    """Fixture has src/dead.ts in the files category (name-only dict shape)."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    files = [f for f in findings if f.rule_id == "unused_file"]
    assert len(files) == 1
    f = files[0]
    assert f.evidence.parsed_value["symbol_name"] == "src/dead.ts"


def test_malformed_json_returns_empty(recorded_tool_output):
    """Truncated JSON ⇒ parser returns [] (no raise)."""
    stdout, stderr, rc = recorded_tool_output("knip", "malformed")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    assert findings == []


def test_non_dict_json_returns_empty():
    """A JSON array (not the expected top-level object) ⇒ []."""
    findings = parse(InvocationResult(stdout="[]"))
    assert findings == []


def test_evidence_parsed_value_keys(recorded_tool_output):
    """parsed_value carries symbol_name / file / line / col / knip_category."""
    stdout, stderr, rc = recorded_tool_output("knip", "issues")
    findings = parse(
        InvocationResult(stdout=stdout, stderr=stderr, returncode=rc)
    )
    for f in findings:
        pv = f.evidence.parsed_value
        assert set(pv.keys()) >= {
            "symbol_name",
            "file",
            "line",
            "col",
            "knip_category",
        }


def test_knip_parser_severity_is_info():
    """D-50 parser-cap invariant pin (replaces prior SCH-04 rung-cap test).

    Per Decision B / D-51' widened, SCH-04 permits severity='major' at
    confidence='candidate' — so the knip-specific D-50 cap is enforced by
    the parser's _KNIP_SEVERITY constant, NOT by the schema validator.
    Pinning the constant catches a maintainer flipping it to 'major'
    (which would NOT trip SCH-04 widened but WOULD violate D-50).
    """
    assert knip_parser._KNIP_SEVERITY == "info"
    assert knip_parser._KNIP_CONFIDENCE == "candidate"


def test_empty_issues_array_returns_empty():
    """Explicit ``{"issues": []}`` ⇒ []."""
    findings = parse(InvocationResult(stdout='{"issues": []}'))
    assert findings == []
