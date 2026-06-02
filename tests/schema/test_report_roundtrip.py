"""FND-02 / D-07-02 — FeedProvenance model + ReportMeta.feed_provenance.

These tests pin the reproducibility-stamp half of FND-02:

  * FeedProvenance constructs with the two Optional fields defaulted.
  * extra="forbid" (D-03) rejects smuggled fields at construction.
  * ReportMeta.feed_provenance defaults to [] (additive Optional list).
  * A Phase 1-6 sidecar STRING (no feed_provenance key) still validates
    via ScanReport.model_validate_json and resolves to feed_provenance == []
    (forward-compat — additive Optional field, schema_version unchanged at "1").
  * A ScanReport WITH provenance entries round-trips bit-identically.
  * extra="forbid" survives on meta through the JSON path (unknown key raises).
"""
from __future__ import annotations

import json
from datetime import date, datetime

import pytest
from pydantic import ValidationError

from repo_audit.schema.report import FeedProvenance, ReportMeta, ScanReport


# --- FeedProvenance model (Task 1 behavior) --------------------------------


def test_feed_provenance_optional_fields_default_none() -> None:
    fp = FeedProvenance(
        feed="OSV",
        scanner="osv-scanner",
        scanner_version="2.3.8",
        queried_at=datetime(2026, 6, 1, 12, 0, 0),
    )
    assert fp.db_snapshot_date is None
    assert fp.advisory_count is None


def test_feed_provenance_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        FeedProvenance(
            feed="OSV",
            scanner="osv-scanner",
            scanner_version="2.3.8",
            queried_at=datetime(2026, 6, 1, 12, 0, 0),
            bogus_field=1,  # type: ignore[call-arg]
        )


def test_report_meta_feed_provenance_defaults_empty() -> None:
    meta = ReportMeta(
        repo_slug="example-repo",
        commit_sha="abc1234",
        scan_date=date(2026, 1, 1),
        tool_version="0.1.0",
    )
    assert meta.feed_provenance == []


# --- Forward-compat: Phase 1-6 sidecar (no feed_provenance key) -------------


def _phase_1_6_sidecar_dict() -> dict:
    """A minimal Phase-1-6-shaped sidecar: meta has NO feed_provenance key
    and NONE of the Phase-4 Optional fields. Simulates an old sidecar.
    """
    return {
        "schema_version": "1",
        "meta": {
            "repo_slug": "example-repo",
            "commit_sha": "abc1234",
            "scan_date": "2026-01-01",
            "tool_version": "0.1.0",
        },
        "findings": [],
        "scope_ledger": {},
    }


def test_phase_1_6_sidecar_validates_to_empty_feed_provenance() -> None:
    json_str = json.dumps(_phase_1_6_sidecar_dict())
    report = ScanReport.model_validate_json(json_str)
    assert report.meta.feed_provenance == []


def test_report_with_feed_provenance_round_trips_identically() -> None:
    report = ScanReport(
        meta=ReportMeta(
            repo_slug="example-repo",
            commit_sha="abc1234",
            scan_date=date(2026, 1, 1),
            tool_version="0.1.0",
            feed_provenance=[
                FeedProvenance(
                    feed="OSV",
                    scanner="osv-scanner",
                    scanner_version="2.3.8",
                    queried_at=datetime(2026, 6, 1, 12, 0, 0),
                ),
                FeedProvenance(
                    feed="GitHub Advisory / NVD (Grype DB)",
                    scanner="grype",
                    scanner_version="0.112.0",
                    db_snapshot_date=date(2026, 5, 30),
                    queried_at=datetime(2026, 6, 1, 12, 0, 1),
                    advisory_count=812345,
                ),
            ],
        ),
    )
    reparsed = ScanReport.model_validate_json(report.model_dump_json())
    assert reparsed.model_dump() == report.model_dump()
    assert len(reparsed.meta.feed_provenance) == 2


def test_meta_extra_forbid_intact_through_json_path() -> None:
    sidecar = _phase_1_6_sidecar_dict()
    sidecar["meta"]["bogus_key"] = 1
    with pytest.raises(ValidationError):
        ScanReport.model_validate_json(json.dumps(sidecar))
