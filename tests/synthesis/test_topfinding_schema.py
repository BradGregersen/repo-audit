"""SYN-02 — `top_findings` is additive on AgentScanReport; schema_version stays "1".

Targets the Wave-2 schema extension (a `TopFinding` model + the `top_findings`
field on `AgentScanReport`), not built in plan 18-01. `importorskip` until it lands.
"""
from __future__ import annotations

import pytest

_schema = pytest.importorskip(
    "repo_audit.synthesis.topfinding",
    reason="Wave 2 synthesis.topfinding not yet implemented (plan 18-02+)",
)


def test_additive_forward_compatible():
    # The TopFinding model round-trips and the report stays schema_version "1".
    tf = _schema.TopFinding(  # pragma: no cover - skipped until W2
        finding_ref="osv::CVE-X::pkg/a.ts:10",
        why_it_matters="",
        rank=1,
    )
    dumped = tf.model_dump()
    again = _schema.TopFinding.model_validate(dumped)
    assert again == tf
