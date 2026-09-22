"""SonarQube JSON normalizer contract (BYO-02, Wave 0 scaffolding).

Pins the SonarQube per-tool JSON->Finding normalizer for Plan 16-06:
  * SonarQube's ``api/issues/search`` (or sonarqube-cli) emits JSON only, so a
    tiny normalizer maps its ``issues[]`` shape into the shared Finding model,
  * the 06-01 candidate cap holds (no candidate+critical finding).

The Sonar JSON is read from the recorded fixture
``tests/adapters/fixtures/sonar/issues.json`` (shape per A5 — LOW confidence,
normalizer must be defensive). ``importorskip`` keeps this SKIPPED until the
normalizer module lands.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

sonar_mod = pytest.importorskip(
    "repo_audit.adapters.byo.sonar_json",
    reason="optional module repo_audit.adapters.byo.sonar_json not importable — feature not present in this build, or the install is incomplete",
)

_SONAR_JSON = (
    Path(__file__).parent.parent / "fixtures" / "sonar" / "issues.json"
)


def _normalize(doc):
    """Invoke the Sonar normalizer, tolerating naming variants."""
    for name in ("sonar_json_to_findings", "normalize_sonar_json", "normalize"):
        fn = getattr(sonar_mod, name, None)
        if fn is not None:
            return fn(doc)
    pytest.fail("byo.sonar_json exposes no normalizer")


def test_sonar_json_to_finding_candidate_cap():
    """Sonar JSON -> Findings tagged source_tool='sonarqube', candidate cap held.

    The normalizer maps the recorded ``issues[]`` shape into Findings honoring
    the same candidate cap as the SARIF path (no candidate+critical).
    """
    doc = json.loads(_SONAR_JSON.read_text(encoding="utf-8"))
    findings = _normalize(doc)
    assert findings, "Sonar normalizer must yield at least one finding"
    for f in findings:
        if f.confidence == "candidate":
            assert f.severity not in ("critical", "blocker")
