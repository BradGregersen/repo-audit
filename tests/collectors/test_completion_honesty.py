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
