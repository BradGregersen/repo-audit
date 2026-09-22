"""SYN-02 — "What matters most" renders right after the exec summary; the
`--no-agent` degrade branch still renders the deterministic section.

Covers the render surface: `synthesis.render.render_what_matters_most` and the
`state_report.md.j2` section. `importorskip` guards the module so this file skips
cleanly in a build where it is not present.
"""
from __future__ import annotations

from datetime import date

import pytest

_render = pytest.importorskip(
    "repo_audit.synthesis.render",
    reason="optional module repo_audit.synthesis.render not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.agent.schema import TopFinding
from repo_audit.render.renderer import render_markdown
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.schema.scope_ledger import ScopeLedger


def _top(why: str = "") -> TopFinding:
    return TopFinding(
        rank=1,
        finding_ref="osv-scanner::CVE-X::pkg/a.ts:10",
        file="pkg/a.ts",
        line=10,
        severity="critical",
        confidence="confirmed",
        composite=0.62,
        band=1,
        dominant_driver="exploitability",
        why_it_matters=why,
    )


def test_what_matters_most_section_placement():
    """The section renders, each item linking a real finding id + file:line."""
    out = _render.render_what_matters_most(top_findings=[_top("It is reachable.")])
    assert "What matters most" in out
    assert "pkg/a.ts:10" in out
    assert "osv-scanner::CVE-X::pkg/a.ts:10" in out
    assert "It is reachable." in out


def test_no_agent_section_renders():
    """--no-agent still renders the deterministic section with empty why_it_matters."""
    out = _render.render_what_matters_most(top_findings=[_top("")])
    # The deterministic spine renders without prose — never crashes on the
    # missing field.
    assert "pkg/a.ts:10" in out
    assert "critical" in out
    assert "exploitability" in out


def test_empty_top_findings_omits_section():
    """Zero eligible findings → the section is empty/omitted (no padding)."""
    out = _render.render_what_matters_most(top_findings=[])
    assert "What matters most" not in out


def _meta() -> ReportMeta:
    return ReportMeta(
        repo_slug="r",
        commit_sha="UNCOMMITTED",
        scan_date=date(2026, 6, 5),
        tool_version="0.0.0-test",
    )


def _scan_report() -> ScanReport:
    f = Finding(
        dimension="security",
        severity="critical",
        file="pkg/a.ts",
        line=10,
        evidence=Evidence(tool="osv-scanner", output_snippet="x", parsed_value={}),
        evidence_type="static",
        confidence="confirmed",
        rule_id="CVE-X",
        source_tool="osv-scanner",
        confidence_caveat="corroborated by a second tool",
    )
    return ScanReport(
        schema_version="1",
        meta=_meta(),
        findings=[f],
        scope_ledger=ScopeLedger(scanned=[], skipped=[], unavailable=[]),
    )


def test_section_after_exec_summary_in_full_render():
    """In the full template the section sits AFTER §1 and BEFORE §2 (no-agent path)."""
    md = render_markdown(_scan_report(), top_findings=[_top("")])
    assert "## What matters most" in md
    # Placement: after the exec summary header, before the scope ledger.
    assert md.index("## 1. Executive summary") < md.index("## What matters most")
    assert md.index("## What matters most") < md.index("## 2. Scope ledger")
    assert "pkg/a.ts:10" in md
