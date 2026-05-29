"""SAFE-07, D-70 — render-time exec-summary curation (Plan 04-08 Task 1).

These test bodies were filled by Plan 04-08 (the stubs landed in Wave 0).
The importorskip gate flips ACTIVE once render/exec_summary.py exists.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_deterministic_header_prepended (SAFE-07/D-70 — deterministic header prepended)
- test_major_dilution_stripped        (D-70 — major-dilution sentence stripped)
- test_partial_dilution_strip         (D-70 — '8 critical, 32 major' → strip only 'major' sentence)
- test_meta_dilution_strips_record    (D-70 — dilution strips recorded into meta)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.exec_summary",
    reason="Wave 1+ plan 04-07 has not landed yet — Wave 0 stub.",
)

from repo_audit.render.exec_summary import (  # noqa: E402
    build_deterministic_exec_header,
    dilution_strip_exec_summary,
)
from repo_audit.schema.finding import Evidence, Finding  # noqa: E402


def _finding(*, severity: str, dimension: str, rule_id: str) -> Finding:
    return Finding(
        dimension=dimension,
        severity=severity,
        file="src/a.ts",
        line=1,
        evidence=Evidence(tool="tsc"),
        evidence_type="static",
        confidence="corroborated",
        rule_id=rule_id,
        source_tool="tsc",
        confidence_caveat="runtime not verified" if severity == "critical" else None,
    )


def test_deterministic_header_prepended():
    """SAFE-07/D-70: a deterministic header is prepended to the exec summary."""
    findings = [
        _finding(severity="blocker", dimension="security", rule_id="B1"),
        _finding(severity="blocker", dimension="quality", rule_id="B2"),
        _finding(severity="critical", dimension="security", rule_id="C1"),
        _finding(severity="critical", dimension="correctness", rule_id="C2"),
        _finding(severity="critical", dimension="process", rule_id="C3"),
    ]
    # 2 blocker, 3 critical, across 4 dimensions (security, quality, correctness, process).
    header = build_deterministic_exec_header(findings)
    assert header == "**2 blocker, 3 critical finding(s)** across 4 dimension(s)."


def test_major_dilution_stripped():
    """D-70: a major-dilution sentence is stripped."""
    clean, stripped = dilution_strip_exec_summary("32 major findings cluster in auth.")
    assert clean == ""
    assert len(stripped) == 1
    assert "32 major findings cluster in auth." in stripped[0]


def test_partial_dilution_strip():
    """D-70: '8 critical, 32 major' → only the 'major' sentence stripped."""
    prose = "8 critical findings. 32 major findings cluster in auth."
    clean, stripped = dilution_strip_exec_summary(prose)
    assert clean == "8 critical findings."
    assert len(stripped) == 1
    assert "32 major findings cluster in auth." in stripped[0]


def test_meta_dilution_strips_record():
    """D-70: dilution strips are recorded into meta."""
    from repo_audit.schema.report import ReportMeta
    from datetime import date

    prose = "Critical issues exist. 14 minor nits clutter the diff."
    clean, stripped = dilution_strip_exec_summary(prose)
    assert clean == "Critical issues exist."
    # The stripped list is exactly what gets stored on meta (D-70).
    meta = ReportMeta(
        repo_slug="x",
        commit_sha="abc",
        scan_date=date.today(),
        tool_version="0.1.0",
        exec_summary_dilution_strips=stripped,
    )
    assert meta.exec_summary_dilution_strips == stripped
    assert len(meta.exec_summary_dilution_strips) == 1
