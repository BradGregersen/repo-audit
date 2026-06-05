"""Socket.dev JSON normalizer contract (BYO-02, Wave 0 scaffolding).

Pins the Socket.dev per-tool JSON->Finding normalizer for Plan 16-06:
  * Socket.dev emits JSON only (no SARIF), so a tiny normalizer maps its
    package/severity/issue-type shape into the shared Finding model,
  * the 06-01 candidate cap holds (no candidate+critical finding).

The Socket JSON is read from the recorded fixture
``tests/adapters/fixtures/socket/scan.json`` (representative + defensive per A6).
``importorskip`` keeps this SKIPPED until the normalizer module lands.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

socket_mod = pytest.importorskip(
    "repo_audit.adapters.byo.socket_json",
    reason="Wave 1/2 (plan 16-06) not yet landed — byo.socket_json missing",
)

_SOCKET_JSON = (
    Path(__file__).parent.parent / "fixtures" / "socket" / "scan.json"
)


def _normalize(doc):
    """Invoke the Socket normalizer, tolerating naming variants."""
    for name in ("socket_json_to_findings", "normalize_socket_json", "normalize"):
        fn = getattr(socket_mod, name, None)
        if fn is not None:
            return fn(doc)
    pytest.fail("byo.socket_json exposes no normalizer")


def test_socket_json_to_finding_candidate_cap():
    """Socket JSON -> Findings tagged source_tool='socket', candidate cap held.

    The normalizer maps the recorded Socket scan shape into Findings; SARIF
    tools cap critical at candidate and this JSON path must honor the same
    candidate cap (no candidate+critical).
    """
    doc = json.loads(_SOCKET_JSON.read_text(encoding="utf-8"))
    findings = _normalize(doc)
    assert findings, "Socket normalizer must yield at least one finding"
    for f in findings:
        if f.confidence == "candidate":
            assert f.severity not in ("critical", "blocker")
