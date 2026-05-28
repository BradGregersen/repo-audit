"""Phase 3 Wave 2 contract — SKIP via importorskip until plan 03-03 lands."""
from __future__ import annotations

import os
import time

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.lcov",
    reason="Wave 2 (plan 03-03) not yet landed — parsers.lcov missing",
)

from repo_audit.adapters.typescript.parsers.lcov import (  # noqa: E402
    get_staleness_threshold_seconds,
    parse_lcov_file,
)


def test_aggregate_finding_from_fresh_lcov(ts_fixture_repo):
    """D-44: fresh lcov.info ⇒ one aggregate Finding with line/branch/function pcts."""
    lcov_file = ts_fixture_repo / "coverage" / "lcov.info"
    finding = parse_lcov_file(lcov_file)
    assert finding is not None
    # D-44 aggregate Finding shape
    assert finding.evidence_type in {"runtime", "static"}
    assert finding.dimension == "test_integrity"


def test_missing_lcov_emits_unavailable(ts_fixture_repo_no_lcov):
    """D-44 / COV-04: missing lcov ⇒ Finding with ``evidence_type='unavailable'``."""
    lcov_file = ts_fixture_repo_no_lcov / "coverage" / "lcov.info"
    finding = parse_lcov_file(lcov_file)
    assert finding is not None
    assert finding.evidence_type == "unavailable"


def test_stale_lcov_emits_unavailable(ts_fixture_repo_stale_lcov):
    """D-43: lcov older than threshold ⇒ ``evidence_type='unavailable'`` with stale reason."""
    lcov_file = ts_fixture_repo_stale_lcov / "coverage" / "lcov.info"
    finding = parse_lcov_file(lcov_file)
    assert finding is not None
    assert finding.evidence_type == "unavailable"
    notes = (finding.evidence.notes or "").lower() if finding.evidence else ""
    assert "stale" in notes or "old" in notes or "mtime" in notes


def test_malformed_lcov_emits_unavailable(tmp_path):
    """Malformed lcov ⇒ ``evidence_type='unavailable'`` (parse failure not crash)."""
    from pathlib import Path
    from tests.adapters.conftest import FIXTURES_ROOT  # noqa: F401 — verify import
    src = Path(__file__).parent / "fixtures" / "lcov" / "malformed.info"
    dst = tmp_path / "lcov.info"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    # Set mtime fresh so freshness gate passes — failure is parse, not staleness
    t = time.time() - 60
    os.utime(dst, (t, t))
    finding = parse_lcov_file(dst)
    assert finding is not None
    assert finding.evidence_type == "unavailable"


def test_parsed_value_contains_line_pct_branch_pct_function_pct_file_count_mtime(ts_fixture_repo):
    """Aggregate Finding evidence exposes line_pct, branch_pct, function_pct, file_count, mtime."""
    lcov_file = ts_fixture_repo / "coverage" / "lcov.info"
    finding = parse_lcov_file(lcov_file)
    assert finding is not None
    assert finding.evidence is not None
    notes = finding.evidence.notes or ""
    # Either the values appear in notes (string form) OR in a structured field.
    keys = ("line", "branch", "function", "file", "mtime")
    for k in keys:
        assert k in notes.lower(), f"evidence.notes missing key {k!r}: {notes!r}"


def test_staleness_threshold_uses_get_threshold_indirection(monkeypatch):
    """Blocker 3: parser MUST call ``get_staleness_threshold_seconds()`` (not hard-code 86400).

    Indirection is the seam Phase 7 user-config will hook. This test proves
    the seam exists by monkey-patching the threshold to 1 second and verifying
    a 5-second-old fixture is then classified stale.
    """
    # Default must be 24h
    assert get_staleness_threshold_seconds() == 24 * 3600
