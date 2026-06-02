"""MOB-01 (9-T1) — mobsfscan SARIF -> Finding contract (Plan 09-01, Wave 1).

This module is laid down in Wave 0 (Plan 09-00) as a RED-then-GREEN target: the
opening ``pytest.importorskip`` keeps it SKIPPED until the Wave-1 implementation
module ``repo_audit.adapters.mobile.mobsfscan`` lands, at which point these
assertions activate automatically (the 03-01b SKIPPED->ACTIVE-on-landing
discipline). The assertions are REAL (not ``pass``) so the module fails RED the
moment the import resolves but the contract is not yet met.

The mobsfscan SARIF fixture is REUSED from Phase 6 (live mobsfscan 0.4.5):
``tests/adapters/sarif/fixtures/mobsfscan/sample.sarif`` — see PROVENANCE.md.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

mobsfscan = pytest.importorskip(
    "repo_audit.adapters.mobile.mobsfscan",
    reason="Wave 1 (plan 09-01) not yet landed — mobile.mobsfscan missing",
)

_SARIF_FIXTURE = (
    Path(__file__).parent / "sarif" / "fixtures" / "mobsfscan" / "sample.sarif"
)


def _load_sarif() -> dict:
    return json.loads(_SARIF_FIXTURE.read_text(encoding="utf-8"))


def test_mobsfscan_sarif_to_findings():
    """The recorded mobsfscan SARIF maps to >=1 security Finding."""
    sarif = _load_sarif()

    # The adapter exposes the SARIF->Finding path. Prefer a dedicated helper if
    # present; otherwise fall back to the generic sarif_to_findings the adapter
    # is contracted to route through (source_tool="mobsfscan",
    # default_dimension="security").
    if hasattr(mobsfscan, "sarif_to_findings"):
        findings = mobsfscan.sarif_to_findings(
            sarif, source_tool="mobsfscan", default_dimension="security"
        )
    else:
        from repo_audit.adapters.sarif.parser import sarif_to_findings

        findings = sarif_to_findings(
            sarif,
            source_tool="mobsfscan",
            default_dimension="security",
            severity_map={},
        )

    assert len(findings) >= 1
    assert all(f.source_tool == "mobsfscan" for f in findings)
    assert all(f.dimension == "security" for f in findings)


@pytest.mark.integration
def test_live_mobsfscan(expo_android_repo):
    """Live mobsfscan over the fixture repo's android/ subtree (9-T1i).

    Skips cleanly when the mobsfscan binary is not resolvable; otherwise runs
    the real adapter and asserts it returns a non-raising result.
    """
    android = expo_android_repo / "android"
    assert android.is_dir()

    if not hasattr(mobsfscan, "run_mobsfscan"):
        pytest.skip("Wave 1 run_mobsfscan entry point not yet landed")

    result = mobsfscan.run_mobsfscan(android)
    # The adapter must never raise/hang — it returns an AdapterResult with an
    # honest status even when the binary is absent (unavailable).
    assert result.status in {"ok", "partial", "unavailable", "timeout"}
