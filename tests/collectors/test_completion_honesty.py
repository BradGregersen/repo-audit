"""completion_honesty_lint chokepoint tests. STRICT — lands in Plan 02-01a Task 2."""
import pytest

from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
    extract_claim_spans,
    format_completion_honesty_diagnostic,
)


def test_partial_scan_blocks_all():
    buf = "we audited all dimensions\n"
    with pytest.raises(CompletionHonestyViolation):
        completion_honesty_lint(buf, partial=True, buffer_name="markdown")


def test_partial_scan_blocks_every_case_insensitive():
    buf = "Every collector ran cleanly\n"
    with pytest.raises(CompletionHonestyViolation):
        completion_honesty_lint(buf, partial=True, buffer_name="markdown")


def test_partial_scan_blocks_complete():
    buf = "Scan complete!\n"
    with pytest.raises(CompletionHonestyViolation):
        completion_honesty_lint(buf, partial=True, buffer_name="markdown")


def test_partial_scan_allows_completed_word_boundary():
    """Word boundary: 'completed' has trailing letters → not a standalone 'complete' token."""
    buf = "task completed without error\n"
    # Should NOT raise (\b prevents partial-word match)
    completion_honesty_lint(buf, partial=True, buffer_name="markdown")


def test_partial_scan_allows_overall_and_fall():
    buf = "overall the fall release covered most cases\n"
    # 'overall' contains 'all' only as substring (no word boundary), 'fall' is not in regex
    completion_honesty_lint(buf, partial=True, buffer_name="markdown")


def test_full_scan_allows_forbidden_words():
    """partial=False ⇒ no-op even if forbidden tokens appear."""
    buf = "All checks complete on every dimension.\n"
    completion_honesty_lint(buf, partial=False, buffer_name="markdown")


def test_phase_one_template_static_prose_passes(synthetic_partial_scan_report):
    """Pitfall 5 mitigation: Phase 1 template's static prose passes lint on partial scan."""
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(synthetic_partial_scan_report)
    # No exception — template prose no longer contains 'complete' standalone.
    completion_honesty_lint(md, partial=True, buffer_name="markdown")


def test_diagnostic_format():
    from repo_audit.render.completion_honesty import CompletionHonestyHit
    hits = [CompletionHonestyHit(line=42, word="all")]
    diag = format_completion_honesty_diagnostic(hits, "markdown")
    assert "REFUSE" in diag
    assert "markdown:42" in diag
    assert "all" in diag


# ---- D-051-11: extract_claim_spans scopes the lint to marked narrative prose. ----


def test_extract_claim_spans_returns_marked_claim_and_lint_raises():
    """A genuine completeness claim inside HONESTY markers is extracted and still
    trips completion_honesty_lint on a partial scan (matcher unchanged)."""
    md = (
        "## 1. Executive summary\n"
        "<!--HONESTY:START-->\n"
        "We audited all dimensions complete.\n"
        "<!--HONESTY:END-->\n"
    )
    spans = extract_claim_spans(md)
    assert "all dimensions complete" in spans
    with pytest.raises(CompletionHonestyViolation):
        completion_honesty_lint(spans, partial=True, buffer_name="markdown")


def test_extract_claim_spans_ignores_unmarked_benign_data_row():
    """A finding-table / scope-ledger DATA row with a benign token sits OUTSIDE any
    marker pair -> not in the extracted span -> extract returns ''. (fail-open)"""
    md = (
        "| Severity | Source | Rule | Evidence |\n"
        "| HIGH | every-file rule | R1 | all files scanned |\n"
        "| `vendor/` | dependencies (every nested dir) |\n"
    )
    spans = extract_claim_spans(md)
    assert spans == ""
    # And so the lint over the extracted spans no-ops even on a partial scan.
    completion_honesty_lint(spans, partial=True, buffer_name="markdown")


def test_extract_claim_spans_returns_all_marker_pairs_joined():
    """Multiple HONESTY pairs (exec summary + a dimension narrative) are both
    returned, joined by a newline; case-insensitive marker matching."""
    md = (
        "<!--HONESTY:START-->\n"
        "First span prose.\n"
        "<!--HONESTY:END-->\n"
        "| data row | every | all |\n"
        "<!--honesty:start-->\n"
        "Second span prose.\n"
        "<!--honesty:end-->\n"
    )
    spans = extract_claim_spans(md)
    assert "First span prose." in spans
    assert "Second span prose." in spans
    assert "data row" not in spans
    assert spans == "First span prose.\nSecond span prose."


def test_template_static_prose_spans_lint_clean(synthetic_partial_scan_report):
    """The rendered template's MARKED claim spans (exec summary + dimension
    narratives) stay clean on a partial scan — extends the spirit of
    test_phase_one_template_static_prose_passes but through the new extractor."""
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(synthetic_partial_scan_report)
    spans = extract_claim_spans(md)
    # No exception — the static prose inside the markers contains no standalone
    # all/every/complete token.
    completion_honesty_lint(spans, partial=True, buffer_name="markdown")


# ---- D-051-11 end-to-end render_and_write contract (Task 3). ----
#
# These prove the SCOPING fix at the render_and_write level: benign all/every/
# complete tokens in finding-table DATA (and therefore in the serialized json
# sidecar) write the report (exit 0), while a genuine completeness CLAIM in the
# claim-bearing narrative prose on a partial scan still hard-refuses (exit 3, no
# write). The first closes the adapt (json) + adapt-garmin (markdown data rows)
# regressions; the second preserves the D-32 / SAFE-08 guarantee.

from datetime import date as _date


def _partial_meta(**overrides):
    from repo_audit.schema.report import ReportMeta
    base = dict(
        repo_slug="d-051-11-test",
        commit_sha="0" * 40,
        scan_date=_date(2026, 5, 29),
        tool_version="0.1.0",
        partial=True,
    )
    base.update(overrides)
    return ReportMeta(**base)


def _benign_finding():
    """A finding whose DATA carries benign all/every/complete tokens. NOT a claim."""
    from repo_audit.schema.finding import Finding, FindingEvidence
    return Finding(
        dimension="quality",
        severity="minor",
        confidence="probable",
        title="every dead export should be removed",
        file="src/all/index.ts",
        line=12,
        rule_id="no-unused",
        source_tool="knip",
        evidence=FindingEvidence(
            evidence_type="violation",
            output_snippet="all files scanned; every export reviewed; coverage complete",
            source_tool="knip",
        ),
    )


def test_partial_benign_finding_data_writes(tmp_path):
    """A partial scan whose finding rows (and thus the json sidecar values) carry
    benign all/every/complete tokens writes both files (exit 0).

    No agent: the markdown benign tokens sit OUTSIDE the HONESTY markers (finding
    table DATA), and the json sidecar is no longer honesty-linted at all."""
    from repo_audit.render import renderer as renderer_mod
    from repo_audit.schema.report import ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    scan_report = ScanReport(
        meta=_partial_meta(),
        findings=[_benign_finding()],
        scope_ledger=ScopeLedger(),
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(scan_report, md_path, json_path)
    assert rc == 0
    assert md_path.exists()
    assert json_path.exists()
    # The benign tokens really are present in the written data (regression proof).
    assert "every" in json_path.read_text(encoding="utf-8")
    assert "all" in md_path.read_text(encoding="utf-8")


def test_partial_genuine_narrative_claim_refuses(tmp_path):
    """A partial scan whose claim-bearing narrative (agent executive_summary,
    which lands inside HONESTY markers) genuinely claims completeness returns 3
    and writes NOTHING — D-32 / SAFE-08 preserved."""
    pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")
    from repo_audit.agent.schema import AgentScanReport
    from repo_audit.render import renderer as renderer_mod
    from repo_audit.schema.report import ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    scan_report = ScanReport(
        meta=_partial_meta(agent_status="ok"),
        findings=[],
        scope_ledger=ScopeLedger(),
    )
    agent_output = AgentScanReport(
        dimensions=[],
        executive_summary="All dimensions were completely audited.",
        cross_cutting_notes=None,
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(
        scan_report, md_path, json_path, agent_output=agent_output,
    )
    assert rc == 3
    assert not md_path.exists()
    assert not json_path.exists()


def test_full_scan_narrative_claim_writes(tmp_path):
    """The SAME genuine completeness claim, but on a full scan (partial=False),
    writes both files (exit 0) — completion-honesty no-ops on full scans."""
    pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")
    from repo_audit.agent.schema import AgentScanReport
    from repo_audit.render import renderer as renderer_mod
    from repo_audit.schema.report import ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    scan_report = ScanReport(
        meta=_partial_meta(partial=False, agent_status="ok"),
        findings=[],
        scope_ledger=ScopeLedger(),
    )
    agent_output = AgentScanReport(
        dimensions=[],
        executive_summary="All dimensions were completely audited.",
        cross_cutting_notes=None,
    )
    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(
        scan_report, md_path, json_path, agent_output=agent_output,
    )
    assert rc == 0
    assert md_path.exists()
    assert json_path.exists()
