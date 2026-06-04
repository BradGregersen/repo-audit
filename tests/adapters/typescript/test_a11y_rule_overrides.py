"""A11Y-01 static tier (Phase 15, Plan 02, Task 1) — eslint a11y glob routing.

The static accessibility tier is a CONFIG-ONLY change: two
``rule_override_globs`` entries (``jsx-a11y/*`` and ``react-native-a11y/*``)
appended to the eslint block of ``adapters/typescript/adapter.yaml`` route a11y
lint to the PUBLIC ``quality`` dimension at ``severity: minor``. This is the
ONLY accessibility path that works for React Native (no DOM → no axe), so the
RN-flavoured ``react-native-a11y/*`` plugin is first-class here.

The eslint parser is UNCHANGED: it already resolves globs at call time, routes
the per-rule ``dimension``, and stamps ``evidence_type="static"`` /
``confidence="high"`` — exactly D-15-07's static-a11y mapping. These tests feed
the Plan-01 ``eslint_a11y.json`` fixture (carrying both a ``jsx-a11y/*`` and a
``react-native-a11y/*`` ruleId) through that unchanged parser and assert the
glob routing.

RED-before-GREEN: WITHOUT the globs a ``severity: 2`` (error) a11y message
defaults to ``quality/major``; the appended glob forces it to ``quality/minor``,
so the ``minor`` assertion below genuinely fails until the descriptor lands.
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.typescript.parsers.eslint import parse

_FIXTURE = (
    Path(__file__).parent.parent
    / "quality_depth"
    / "fixtures"
    / "eslint_a11y.json"
)


def _parse_fixture() -> list:
    stdout = _FIXTURE.read_text(encoding="utf-8")
    return parse(InvocationResult(stdout=stdout, stderr="", returncode=1))


def test_jsx_a11y_routes_to_quality_static() -> None:
    """A ``jsx-a11y/*`` message routes to dimension=quality, evidence_type=static."""
    findings = _parse_fixture()
    jsx = [f for f in findings if f.rule_id.startswith("jsx-a11y/")]
    assert jsx, "fixture carries jsx-a11y/* messages"
    for f in jsx:
        assert f.dimension == "quality"
        assert f.evidence_type == "static"
        assert f.confidence == "high"
        # The glob pins severity=minor regardless of the eslint int level —
        # WITHOUT the glob, a severity-2 (error) message would default to major.
        assert f.severity == "minor"


def test_react_native_a11y_routes_to_quality_static() -> None:
    """A ``react-native-a11y/*`` message routes to quality/static (the RN tier)."""
    findings = _parse_fixture()
    rn = [f for f in findings if f.rule_id.startswith("react-native-a11y/")]
    assert rn, "fixture carries react-native-a11y/* messages"
    for f in rn:
        assert f.dimension == "quality"
        assert f.evidence_type == "static"
        assert f.confidence == "high"
        assert f.severity == "minor"


def test_a11y_globs_present_in_descriptor() -> None:
    """Both a11y globs live under the eslint ``rule_override_globs`` (quality)."""
    from repo_audit.adapters.typescript import CONFIG

    globs = CONFIG["tools"]["eslint"]["rule_override_globs"]
    patterns = {g["pattern"]: g for g in globs}
    assert "jsx-a11y/*" in patterns
    assert "react-native-a11y/*" in patterns
    assert patterns["jsx-a11y/*"]["dimension"] == "quality"
    assert patterns["react-native-a11y/*"]["dimension"] == "quality"


def test_fixture_carries_both_a11y_plugins() -> None:
    """Guard: the shared fixture must keep at least one of each a11y plugin."""
    doc = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    rule_ids = {
        m.get("ruleId", "")
        for entry in doc
        for m in entry.get("messages", [])
    }
    assert any(r.startswith("jsx-a11y/") for r in rule_ids)
    assert any(r.startswith("react-native-a11y/") for r in rule_ids)
