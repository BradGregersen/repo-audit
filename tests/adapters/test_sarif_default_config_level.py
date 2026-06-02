"""D-10-03 parser fix — pins the Semgrep severity-collapse repair (Plan 10-01).

This module is laid down in Wave 0 (Plan 10-00) and is **NOT** importorskip-gated:
it tests the ALREADY-EXISTING shared parser
(``repo_audit.adapters.sarif.parser.sarif_to_findings``), which Wave 1
extends with the ``rule.defaultConfiguration.level`` fallback (D-10-03).

``test_semgrep_level_from_default_configuration`` runs **RED today** — the current
parser reads ``result.level`` only, so Semgrep's ``result.level=null`` floors
every finding to ``info``. It goes GREEN the moment Wave-1 plan 01 lands the
fallback that reads the faithful severity from the rule's
``defaultConfiguration.level``.

``test_existing_corpus_unaffected`` pins the gate so the Wave-1 fix can ONLY fire
when ``result.level is None`` — an existing 8-tool-corpus fixture that DOES set
``result.level`` must keep its severities unchanged (no regression).

Pitfall-1 reference (10-RESEARCH § Common Pitfalls 1): Semgrep sets
``result.level = null`` and the faithful severity lives in
``runs[].tool.driver.rules[].defaultConfiguration.level``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_audit.adapters.sarif.parser import sarif_to_findings

_FIXTURES = Path(__file__).parent / "fixtures"
_SARIF_CORPUS = Path(__file__).parent / "sarif" / "fixtures"


def _load_owasp() -> dict:
    return json.loads(
        (_FIXTURES / "sast" / "owasp_top_ten.sarif").read_text(encoding="utf-8")
    )


def test_semgrep_level_from_default_configuration():
    """RED-until-Wave-1: result.level=null must fall back to defaultConfiguration.level.

    The owasp fixture's first result has ``ruleId`` for the
    ``defaultConfiguration.level == "error"`` rule and ``result.level == null``.
    A faithful ``error`` maps to ``critical`` (capped to ``major`` at
    confidence=candidate per SCH-04). The CURRENT parser floors null-level to
    ``info`` — this test FAILS RED today and goes GREEN at Wave 1.
    """
    sarif = _load_owasp()
    findings = sarif_to_findings(
        sarif,
        source_tool="semgrep",
        default_dimension="security",
        severity_map={},
    )
    assert findings, "owasp fixture must yield findings"

    # Locate the finding for the defaultConfiguration.level=="error" rule.
    error_rule_id = next(
        rule["id"]
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        if rule.get("defaultConfiguration", {}).get("level") == "error"
    )
    error_finding = next(f for f in findings if f.rule_id == error_rule_id)

    # Faithful severity must be derived from the rule default, NOT floored to info.
    assert error_finding.severity != "info", (
        "Wave-1 D-10-03 fix not yet landed: result.level=null floored to info "
        "instead of falling back to rule.defaultConfiguration.level"
    )
    assert (
        error_finding.evidence.parsed_value["faithful_severity"] == "critical"
    ), "error-level rule must yield faithful 'critical' (capped to major)"
    # SCH-04 cap: the visible severity is 'major' at confidence=candidate.
    assert error_finding.severity == "major"
    assert error_finding.confidence == "candidate"


def test_existing_corpus_unaffected():
    """The fix fires ONLY when result.level is None — corpus stays unchanged.

    The osv-scanner corpus fixture sets ``result.level = "warning"`` explicitly.
    Parsing it must yield the same severities before and after the Wave-1 fix
    (the fallback must not touch findings that already carry a level). This pins
    the "only when result.level is None" gate so the fix can't regress the
    8-tool corpus.
    """
    osv = json.loads(
        (_SARIF_CORPUS / "osv-scanner" / "sample.sarif").read_text(encoding="utf-8")
    )
    # Sanity: the fixture sets explicit non-null levels (the gate's precondition).
    levels = [r.get("level") for r in osv["runs"][0]["results"]]
    assert any(lvl is not None for lvl in levels), (
        "osv corpus fixture must set explicit result.level for this gate test"
    )

    findings = sarif_to_findings(
        osv,
        source_tool="osv-scanner",
        default_dimension="security",
        severity_map={},
    )
    assert findings, "osv corpus fixture must yield findings"

    # A warning-level result maps to faithful 'major'. This is the contract the
    # Wave-1 fix must NOT change (it only adds a null-level fallback).
    for finding in findings:
        if finding.evidence.parsed_value.get("sarif_level") == "warning":
            assert finding.evidence.parsed_value["faithful_severity"] == "major"
            assert finding.severity == "major"
