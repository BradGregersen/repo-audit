"""Phase 3 Wave 2 (plan 03-03): lcov parser contract tests.

Replaces Wave 0b scaffolding (the previous test bodies were authored
against an evidence-schema shape with ``evidence.notes`` that does not
match the current Phase-1 Evidence schema, and against a different
public API ``parse_lcov_file``/``get_staleness_threshold_seconds``). The
plan instructs the executor to ship ``parse_from_repo(repo_path)`` and
``_refresh_failed_finding(refresh_result, runner_command)`` and to
implement these contract tests.

The opening ``pytest.importorskip`` line is retained so the module
SKIPS cleanly when the parser is absent and flips ACTIVE once the
symbols land (per plan 03-01b Warning-8 pattern).
"""
from __future__ import annotations

import inspect
import os
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.lcov",
    reason="Wave 2 (plan 03-03) not yet landed — parsers.lcov missing",
)

from repo_audit.adapters.typescript.parsers import lcov as lcov_parser  # noqa: E402
from repo_audit.adapters.typescript.parsers.lcov import (  # noqa: E402
    _refresh_failed_finding,
    _unavailable_finding,
    parse_from_repo,
)

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


# --- fresh / D-44 aggregate ----------------------------------------------


def test_aggregate_finding_from_fresh_lcov(ts_fixture_repo):
    """D-44: fresh lcov.info ⇒ exactly ONE aggregate Finding."""
    findings = parse_from_repo(ts_fixture_repo)
    assert isinstance(findings, list)
    assert len(findings) == 1


def test_fresh_finding_dimension_severity_evidence_type(ts_fixture_repo):
    """D-44 fresh: dimension/severity/evidence_type/confidence/caveat shape."""
    finding = parse_from_repo(ts_fixture_repo)[0]
    assert finding.dimension == "test_integrity"
    assert finding.severity == "major"
    assert finding.evidence_type == "static"
    assert finding.confidence == "high"
    assert finding.confidence_caveat is not None
    assert finding.confidence_caveat.strip() != ""
    assert finding.rule_id == "coverage_summary"
    assert finding.source_tool == "lcov"
    assert finding.source_collector == "typescript_adapter"
    assert "lcov.info" in finding.recommendation


def test_fresh_finding_parsed_value_keys(ts_fixture_repo):
    """parsed_value contains exactly the documented set of keys."""
    finding = parse_from_repo(ts_fixture_repo)[0]
    assert set(finding.evidence.parsed_value.keys()) == {
        "total_pct",
        "line_pct",
        "branch_pct",
        "function_pct",
        "file_count",
        "artifact_mtime_iso",
    }


def test_fresh_finding_computed_values(ts_fixture_repo):
    """Fixture: LF=3+2=5, LH=2+2=4 ⇒ line_pct=80.0; BRF=2 BRH=1 ⇒ 50.0;
    FNF=1 FNH=1 ⇒ 100.0; file_count=2."""
    finding = parse_from_repo(ts_fixture_repo)[0]
    pv = finding.evidence.parsed_value
    assert pv["line_pct"] == 80.0
    assert pv["total_pct"] == 80.0
    assert pv["branch_pct"] == 50.0
    assert pv["function_pct"] == 100.0
    assert pv["file_count"] == 2


def test_artifact_mtime_iso_is_valid_iso8601_utc(ts_fixture_repo):
    """artifact_mtime_iso is parseable ISO-8601 with UTC offset."""
    finding = parse_from_repo(ts_fixture_repo)[0]
    raw = finding.evidence.parsed_value["artifact_mtime_iso"]
    # datetime.fromisoformat handles '+00:00' style suffixes.
    parsed = datetime.fromisoformat(raw)
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 0.0


# --- missing / stale / malformed: COV-04 unavailable Findings -----------


def test_missing_lcov_emits_unavailable(ts_fixture_repo_no_lcov):
    """No coverage/lcov.info ⇒ unavailable Finding."""
    findings = parse_from_repo(ts_fixture_repo_no_lcov)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence_type == "unavailable"
    assert f.rule_id == "coverage_unavailable"
    assert f.evidence.parsed_value["reason"] == "stale_or_missing_coverage_artifact"


def test_stale_lcov_emits_unavailable(ts_fixture_repo_stale_lcov):
    """D-43: 25h-old lcov ⇒ unavailable Finding (same shape as missing)."""
    findings = parse_from_repo(ts_fixture_repo_stale_lcov)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence_type == "unavailable"
    assert f.rule_id == "coverage_unavailable"
    assert f.evidence.parsed_value["reason"] == "stale_or_missing_coverage_artifact"


def test_malformed_lcov_emits_unavailable(tmp_path):
    """Malformed LCOV ⇒ unavailable Finding with lcov_parse_failed reason."""
    repo = tmp_path / "malformed-repo"
    (repo / "coverage").mkdir(parents=True)
    src = FIXTURES_ROOT / "lcov" / "malformed.info"
    dst = repo / "coverage" / "lcov.info"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    # mtime fresh so the staleness gate passes — failure is parse, not stale
    t = time.time() - 60
    os.utime(dst, (t, t))
    findings = parse_from_repo(repo)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence_type == "unavailable"
    assert f.evidence.parsed_value["reason"] == "lcov_parse_failed"


def test_unavailable_finding_severity_is_major(ts_fixture_repo_no_lcov):
    """Unavailable coverage is still surfaced loudly (severity=major)."""
    f = parse_from_repo(ts_fixture_repo_no_lcov)[0]
    assert f.severity == "major"


# --- structural / safety guards -----------------------------------------


def test_only_reads_coverage_lcov_info_path(monkeypatch, tmp_path):
    """T-03-10 mitigation: parser only checks <repo>/coverage/lcov.info — no path traversal.

    We trace Path.is_file by wrapping the original; assert the parser only
    asked about coverage/lcov.info (relative to repo).
    """
    repo = tmp_path / "no-lcov-repo"
    repo.mkdir()
    asked: list[str] = []
    original_is_file = Path.is_file

    def _tracing_is_file(self):
        asked.append(str(self))
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", _tracing_is_file)
    parse_from_repo(repo)
    # Every path the parser asked about must be the one canonical relative
    # path (or a child thereof — which it isn't, but be defensive).
    expected = str(repo / "coverage" / "lcov.info")
    for path in asked:
        assert path == expected, (
            f"parser inspected unexpected path {path!r}; only {expected!r} allowed"
        )


def test_staleness_threshold_uses_get_threshold_indirection(
    monkeypatch, tmp_path
):
    """Blocker 3: parser reads CONFIG['tools']['coverage_lcov']['staleness_hours'].

    Override the staleness threshold to 48h; create a fixture whose lcov.info
    is 30h old (between the default 24h and the override 48h). The parser
    MUST return the fresh aggregate Finding because the indirection wins.
    """
    from repo_audit.adapters.typescript import CONFIG

    original_hours = CONFIG["tools"]["coverage_lcov"]["staleness_hours"]
    try:
        CONFIG["tools"]["coverage_lcov"]["staleness_hours"] = 48
        repo = tmp_path / "30h-repo"
        (repo / "coverage").mkdir(parents=True)
        src = FIXTURES_ROOT / "lcov" / "fresh.info"
        dst = repo / "coverage" / "lcov.info"
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        t = time.time() - (30.0 * 3600.0)
        os.utime(dst, (t, t))
        findings = parse_from_repo(repo)
        assert len(findings) == 1
        f = findings[0]
        # Under default 24h this would be unavailable; under override 48h it's fresh.
        assert f.evidence_type == "static", (
            f"override staleness threshold not honored — got {f.evidence_type!r}; "
            f"the parser must read through _get_staleness_hours() (CONFIG), not "
            f"hardcoded STALENESS_HOURS_DEFAULT."
        )
        assert f.rule_id == "coverage_summary"
    finally:
        CONFIG["tools"]["coverage_lcov"]["staleness_hours"] = original_hours


def test_unavailable_finding_constructs_cleanly_under_schema():
    """SCH-03 + SCH-04 widened: unavailable+major+medium constructs fine.

    Sanity guard per plan 03-03 checker Warning 12 — verifies the
    _unavailable_finding helper doesn't trip the SCH-03 critical+static
    caveat rule (severity is 'major', not 'critical') or the SCH-04
    widened candidate-rung rule (confidence is 'medium', not 'candidate').
    """
    f = _unavailable_finding(reason="x", detail="y")
    assert f.evidence_type == "unavailable"
    assert f.severity == "major"
    assert f.confidence == "medium"
    assert f.rule_id == "coverage_unavailable"


def test_streaming_read_uses_for_line():
    """Pitfall 14: parser MUST stream lcov, not read_text() the whole file."""
    src = inspect.getsource(lcov_parser)
    assert "for raw in f" in src or "for line in f" in src, (
        "lcov parser must use streaming `for ... in f` over lcov.info"
    )
    assert "read_text" not in src, (
        "lcov parser must NOT use read_text() on lcov.info (Pitfall 14)"
    )


# --- Decision C: _refresh_failed_finding helper -------------------------


def test_refresh_failed_finding_constructs_under_extended_schema():
    """Decision C / plan 03-01a 'failed' EvidenceType variant.

    The helper synthesises a Finding from a RefreshResult-shaped object
    when the coverage-refresh subprocess (plan 03-06) fails. Plan 03-06
    has not shipped yet, so we use a SimpleNamespace stub matching the
    expected attribute surface (status / runner_command / duration_ms /
    stdout_tail / stderr_tail / lcov_produced / notes).

    SCH-03 critical+static caveat: NOT triggered (evidence_type='failed').
    SCH-04 widened candidate rung-cap: NOT triggered (confidence='medium').
    """
    rr = SimpleNamespace(
        status="failed",
        runner_command=["npm", "test"],
        duration_ms=1234.5,
        stdout_tail="",
        stderr_tail="runner exited 1\nsome error",
        lcov_produced=False,
        notes="runner exited 1",
    )
    f = _refresh_failed_finding(rr, ["npm", "test"])

    # Shape contract
    assert f.evidence_type == "failed"
    assert f.severity == "major"
    assert f.confidence == "medium"
    assert f.dimension == "test_integrity"
    assert f.source_tool == "coverage_refresh"
    assert f.source_collector == "lcov"
    assert f.rule_id == "coverage_refresh_failed"
    # SCH-03 does NOT trigger for evidence_type='failed' — caveat may be None.
    assert f.confidence_caveat is None

    # parsed_value carries the runner's diagnostic envelope.
    pv = f.evidence.parsed_value
    assert pv["reason"] == "coverage_refresh_failed"
    assert pv["runner_command"] == ["npm", "test"]
    assert pv["stderr_tail"] == "runner exited 1\nsome error"
    assert pv["duration_ms"] == 1234.5


def test_refresh_failed_finding_is_sole_emitter_of_rule_id():
    """The helper is the ONLY emitter of rule_id='coverage_refresh_failed'.

    Pins the structural assertion that no other code path in the lcov
    parser module emits this rule_id (defensive — protects against
    accidental duplication during future refactors).
    """
    src = inspect.getsource(lcov_parser)
    occurrences = src.count('rule_id="coverage_refresh_failed"') + src.count(
        "rule_id='coverage_refresh_failed'"
    )
    assert occurrences == 1, (
        f"expected exactly one literal emission of "
        f"rule_id='coverage_refresh_failed' in parsers/lcov.py; "
        f"found {occurrences} — the helper must be the sole emitter."
    )
