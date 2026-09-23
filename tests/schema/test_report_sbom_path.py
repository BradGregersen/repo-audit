"""SUP-02 / D-12-07 — ReportMeta.sbom_path additive Optional field (Plan 12-05).

Pins the path-reference half of SUP-02 on the schema:

  * ReportMeta.sbom_path defaults to None (additive Optional field).
  * A Phase 1-11 sidecar STRING (no sbom_path key) still validates via
    ScanReport.model_validate_json and resolves to sbom_path == None
    (forward-compat — additive Optional field, schema_version unchanged at "1").
  * sbom_path carries a PATH string when set (D-12-07: reference by path, never
    the inlined SBOM document); the round-trip preserves it.
  * extra="forbid" (D-03) still rejects a smuggled field on meta.
  * schema_version stays "1" — additive Optional fields are forward-compatible.
"""
from __future__ import annotations

import json
from datetime import date

import pytest
from pydantic import ValidationError

from repo_audit.schema.report import ReportMeta, ScanReport


def test_report_meta_sbom_path_defaults_none() -> None:
    """A freshly-built ReportMeta has sbom_path None (nothing generated yet)."""
    meta = ReportMeta(
        repo_slug="example-repo",
        commit_sha="abc1234",
        scan_date=date(2026, 1, 1),
        tool_version="0.1.0",
    )
    assert meta.sbom_path is None


def test_report_meta_sbom_path_carries_reference_path() -> None:
    """sbom_path holds the REFERENCE path (D-12-07: never the inlined document)."""
    ref = "/opt/repo-audit/reports/example-app-sbom-2026-06-03.json"
    meta = ReportMeta(
        repo_slug="example-app",
        commit_sha="deadbee",
        scan_date=date(2026, 6, 3),
        tool_version="0.1.0",
        sbom_path=ref,
    )
    assert meta.sbom_path == ref
    # It is a plain path string — not a dict / list (the SBOM document itself).
    assert isinstance(meta.sbom_path, str)


def test_phase7_era_sidecar_no_sbom_path_validates() -> None:
    """A Phase-7-era sidecar (no sbom_path key) round-trip-validates → None.

    schema_version stays "1": the additive Optional field is forward-compatible,
    so an older sidecar with no sbom_path key still loads cleanly.
    """
    sidecar = {
        "schema_version": "1",
        "meta": {
            "repo_slug": "legacy-repo",
            "commit_sha": "0badf00",
            "scan_date": "2026-02-01",
            "tool_version": "0.1.0",
            # NOTE: no sbom_path key — the Phase 1-11 era.
        },
        "findings": [],
        "scope_ledger": {
            "scanned": [],
            "skipped": [],
            "unavailable": [],
            "notes": "",
        },
    }
    report = ScanReport.model_validate_json(json.dumps(sidecar))
    assert report.schema_version == "1"
    assert report.meta.sbom_path is None


def test_sbom_path_round_trips() -> None:
    """A ScanReport carrying sbom_path serializes + reloads bit-identically."""
    ref = "/x/reports/repo-sbom-2026-06-03.json"
    meta = ReportMeta(
        repo_slug="repo",
        commit_sha="cafe123",
        scan_date=date(2026, 6, 3),
        tool_version="0.1.0",
        sbom_path=ref,
    )
    report = ScanReport(meta=meta)
    reloaded = ScanReport.model_validate_json(report.model_dump_json())
    assert reloaded.meta.sbom_path == ref
    assert reloaded.schema_version == "1"


def test_meta_still_forbids_unknown_field_with_sbom_path_present() -> None:
    """extra='forbid' (D-03) survives the additive field — a smuggled key raises."""
    with pytest.raises(ValidationError):
        ReportMeta(
            repo_slug="repo",
            commit_sha="abc1234",
            scan_date=date(2026, 1, 1),
            tool_version="0.1.0",
            sbom_path="/x/y.json",
            bogus_field=1,  # type: ignore[call-arg]
        )
