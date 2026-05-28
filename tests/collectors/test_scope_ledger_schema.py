"""ScopeLedger schema round-trip tests. STRICT — lands in Plan 02-01a Task 2."""
import json
from datetime import date

from repo_audit.schema import (
    ReportMeta,
    ScannedEntry,
    ScanReport,
    ScopeLedger,
    SkippedEntry,
    UnavailableEntry,
)


def test_scope_ledger_default_empty():
    sl = ScopeLedger()
    assert sl.scanned == []
    assert sl.skipped == []
    assert sl.unavailable == []
    assert sl.notes == ""


def test_scope_ledger_round_trips_through_json():
    sl = ScopeLedger(
        scanned=[ScannedEntry(dir="src", file_count=42, collectors=["loc_inventory"])],
        skipped=[SkippedEntry(dir="node_modules", reason="dependencies")],
        unavailable=[UnavailableEntry(dimension="security", collector="secret_detection", reason="gitleaks not on PATH")],
        notes="walker hit cap",
    )
    round = ScopeLedger.model_validate_json(sl.model_dump_json())
    assert round == sl


def test_skipped_reason_literal_enforced():
    from pydantic import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        SkippedEntry(dir="foo", reason="not_a_reason")  # type: ignore[arg-type]


def test_extra_forbidden_on_all_models():
    from pydantic import ValidationError
    import pytest
    for cls, valid in [
        (ScopeLedger, {}),
        (ScannedEntry, {"dir": "x", "file_count": 0}),
        (SkippedEntry, {"dir": "x", "reason": "vcs"}),
        (UnavailableEntry, {"dimension": "x", "collector": "y", "reason": "z"}),
    ]:
        with pytest.raises(ValidationError):
            cls(**valid, sneaky="boom")  # type: ignore[arg-type]


def test_scan_report_carries_scope_ledger_and_partial():
    meta = ReportMeta(
        repo_slug="x", commit_sha="0"*40, scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
    )
    # Phase 1 default — both fields optional
    sr = ScanReport(schema_version="1", meta=meta)
    assert sr.scope_ledger == ScopeLedger()
    assert sr.meta.partial is False
    # Phase 2 usage
    meta2 = ReportMeta(
        repo_slug="x", commit_sha="0"*40, scan_date=date(2026, 5, 28),
        tool_version="0.1.0", partial=True,
    )
    sr2 = ScanReport(
        schema_version="1", meta=meta2,
        scope_ledger=ScopeLedger(skipped=[SkippedEntry(dir="dist", reason="build-artifact")]),
    )
    assert sr2.meta.partial is True
    assert len(sr2.scope_ledger.skipped) == 1


def test_phase_one_empty_scan_report_still_constructs():
    """Regression: Phase 1's ScanReport(schema_version='1', meta=ReportMeta(...)) MUST stay valid."""
    meta = ReportMeta(
        repo_slug="x", commit_sha="0"*40, scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
    )
    sr = ScanReport(schema_version="1", meta=meta, findings=[])
    # Round-trip through JSON to ensure backward-compat with Phase 1 sidecars
    parsed = json.loads(sr.model_dump_json())
    assert parsed["schema_version"] == "1"
