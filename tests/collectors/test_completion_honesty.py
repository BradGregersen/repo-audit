"""completion_honesty_lint chokepoint tests. STRICT — lands in Plan 02-01a Task 2."""
import pytest

from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
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
