"""DAST evidence-type contract (DAST-01, Wave 0 scaffolding).

Pins the heuristic-not-runtime policy for Plan 16-05:
  * ZAP baseline findings land ``evidence_type='heuristic'`` (a passive baseline
    scan is not a runtime exploit proof),
  * a post-pass assertion FORBIDS ``evidence_type='runtime'`` from this lane —
    runtime is reserved for the Supabase two-account test (Phase 8) only.

The ZAP JSON is read from the recorded fixture
``tests/adapters/fixtures/zap/baseline.json``. ``importorskip`` keeps this
SKIPPED until ``repo_audit.adapters.dast`` lands.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

dast = pytest.importorskip(
    "repo_audit.adapters.dast",
    reason="Wave 1/2 (plan 16-05) not yet landed — adapters.dast missing",
)

_ZAP_JSON = Path(__file__).parent.parent / "fixtures" / "zap" / "baseline.json"


def _normalize(doc):
    """Invoke the lane's ZAP-JSON normalizer, tolerating naming variants."""
    for name in ("normalize_zap_json", "zap_json_to_findings", "normalize", "parse_zap"):
        fn = getattr(dast, name, None)
        if fn is not None:
            return fn(doc)
    pytest.fail("adapters.dast exposes no ZAP-JSON normalizer")


def test_findings_heuristic_never_runtime():
    """ZAP findings land ``heuristic``; the post-pass forbids ``runtime``.

    The fixture carries ``site[].alerts[]`` with riskcode bands; every Finding
    the lane produces must be ``evidence_type='heuristic'`` and never ``runtime``.
    """
    doc = json.loads(_ZAP_JSON.read_text(encoding="utf-8"))
    assert doc.get("site"), "ZAP fixture must carry site[].alerts[]"

    findings = _normalize(doc)
    assert findings, "ZAP normalizer must yield at least one finding"
    for f in findings:
        assert f.evidence_type == "heuristic"
        assert f.evidence_type != "runtime"
