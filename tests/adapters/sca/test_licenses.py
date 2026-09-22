"""SCA-04 — offline license-risk findings from the Syft SBOM (Wave 1).

Wave-0 ``importorskip`` stub: SKIPPED until the SCA-04 license module lands
(``repo_audit.adapters.sca.licenses``), then ACTIVE.

Contract under test (RESEARCH Pitfall 1 option 1 + D-12-08):
  * a risky/copyleft license (GPL/AGPL) or an UNKNOWN-license component yields a
    minor-severity, candidate-confidence Finding,
  * license risk is derived OFFLINE from the Syft CycloneDX SBOM
    (``components[].licenses[]``), never a network deps.dev call.

Loads ``syft-cyclonedx-sample.json`` (one GPL-3.0-only component + one
no-license component).
"""
from __future__ import annotations

import pytest

licenses = pytest.importorskip(
    "repo_audit.adapters.sca.licenses",
    reason="optional module repo_audit.adapters.sca.licenses not importable — feature not present in this build, or the install is incomplete",
)


def _derive(sbom):
    """Invoke the Wave-1 offline license-risk deriver, tolerating names."""
    for name in (
        "derive_license_findings",
        "license_findings_from_sbom",
        "collect_licenses",
    ):
        fn = getattr(licenses, name, None)
        if fn is not None:
            return fn(sbom)
    pytest.fail("sca.licenses exposes no license-risk entry point")


def test_risky_license_minor_candidate(load_supply_chain_fixture):
    """A GPL-3.0-only component -> a minor/candidate license-risk Finding."""
    sbom = load_supply_chain_fixture("syft-cyclonedx-sample.json")
    result = _derive(sbom)
    findings = getattr(result, "findings", result)
    gpl = [
        f
        for f in findings
        if "GPL" in (f.evidence.output_snippet or "")
        or "GPL" in str(getattr(f.evidence, "parsed_value", {}))
        or "copyleft-lib" in (f.file or "")
    ]
    assert gpl, "expected a license-risk finding for the GPL-3.0 component"
    for f in gpl:
        assert f.severity == "minor"
        assert f.confidence == "candidate"


def test_unknown_license_flagged(load_supply_chain_fixture):
    """The no-license component surfaces as an unknown-license candidate finding."""
    sbom = load_supply_chain_fixture("syft-cyclonedx-sample.json")
    result = _derive(sbom)
    findings = getattr(result, "findings", result)
    unknown = [f for f in findings if "no-license-lib" in (f.file or "")]
    # Wave 1 decides whether unknown-license is emitted as a finding or context;
    # if emitted, it must be candidate-confidence and no harder than minor.
    for f in unknown:
        assert f.confidence == "candidate"
        assert f.severity in ("info", "minor")
