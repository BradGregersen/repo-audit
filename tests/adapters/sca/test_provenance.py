"""Task 1 (Plan 07-05): FeedProvenance builder (provenance.py).

``build_feed_provenance`` emits ONE FeedProvenance entry per AVAILABLE scanner:
the osv entry always (osv is the floor), the grype entry only when grype ran ok.
advisory_count is None unless cleanly obtainable; numbers are never invented.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from repo_audit.adapters.sca.grype import GrypeResult
from repo_audit.adapters.sca.osv import OsvResult
from repo_audit.adapters.sca.provenance import build_feed_provenance
from repo_audit.schema.report import FeedProvenance

_QUERIED = datetime(2026, 6, 2, 3, 0, 0, tzinfo=timezone.utc)


def test_osv_only_emits_single_entry():
    osv = OsvResult(status="ok", scanner_version="2.3.8", findings=[])
    grype = GrypeResult(status="unavailable", findings=[])
    prov = build_feed_provenance(osv, grype, queried_at=_QUERIED)
    assert len(prov) == 1
    entry = prov[0]
    assert isinstance(entry, FeedProvenance)
    assert entry.feed == "OSV"
    assert entry.scanner == "osv-scanner"
    assert entry.scanner_version == "2.3.8"
    assert entry.queried_at == _QUERIED
    assert entry.advisory_count is None


def test_both_available_emits_two_entries():
    osv = OsvResult(status="ok", scanner_version="2.3.8", findings=[])
    grype = GrypeResult(
        status="ok",
        scanner_version="0.112.0",
        db_snapshot_date="2026-06-01T08:11:23Z",
        findings=[],
    )
    prov = build_feed_provenance(osv, grype, queried_at=_QUERIED)
    assert len(prov) == 2
    by_scanner = {p.scanner: p for p in prov}
    assert set(by_scanner) == {"osv-scanner", "grype"}
    g = by_scanner["grype"]
    assert g.feed == "GitHub Advisory / NVD (Grype DB)"
    assert g.scanner_version == "0.112.0"
    assert g.db_snapshot_date == date(2026, 6, 1)
    # grype advisory_count is unobtainable → None (A3).
    assert g.advisory_count is None


def test_grype_unavailable_no_grype_entry():
    osv = OsvResult(status="ok", scanner_version="2.3.8", findings=[])
    grype = GrypeResult(status="timeout", findings=[])
    prov = build_feed_provenance(osv, grype, queried_at=_QUERIED)
    assert [p.scanner for p in prov] == ["osv-scanner"]


def test_osv_db_snapshot_from_db_file_mtime(monkeypatch, tmp_path):
    """osv db_snapshot_date comes from the osv DB file mtime (A2), or None."""
    import repo_audit.adapters.sca.provenance as provmod

    fake_db = tmp_path / "vuln-db"
    osv_sub = fake_db / "osv"
    osv_sub.mkdir(parents=True)
    # Seed a DB file with a known mtime.
    db_file = osv_sub / "all.zip"
    db_file.write_bytes(b"x")
    import os
    import time

    ts = time.mktime(date(2026, 5, 30).timetuple())
    os.utime(db_file, (ts, ts))
    monkeypatch.setattr(provmod, "sca_db_dir", lambda: fake_db)

    osv = OsvResult(status="ok", scanner_version="2.3.8", findings=[])
    grype = GrypeResult(status="unavailable", findings=[])
    prov = build_feed_provenance(osv, grype, queried_at=_QUERIED)
    assert prov[0].db_snapshot_date == date(2026, 5, 30)
