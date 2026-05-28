"""Secret-lint chokepoint tests. Implementation lands in Plan 05 (Wave 2)."""
import pytest

pytestmark = pytest.mark.xfail(strict=False, reason="Plan 05 implements secret_lint")


def test_renderer_refuses_on_synthetic_secret(synthetic_secret, fake_repo, runner, tmp_path):
    """SC-5 / REP-05 — secret-lint refuses to write when high-entropy token in render buffer."""
    # Build a ScanReport whose narrative slot will contain the synthetic secret.
    # The renderer's secret-lint must catch it BEFORE either file reaches disk.
    from repo_audit.render.secret_lint import lint_buffer, SecretsDetected
    buf = f"normal text\nleaked: {synthetic_secret}\nmore text\n"
    with pytest.raises(SecretsDetected):
        lint_buffer(buf, buffer_name="markdown")


def test_secret_lint_blocks_write_in_render_pipeline(synthetic_secret, fake_repo, tmp_path, monkeypatch):
    """REP-05 — full render_and_write pipeline aborts (exit nonzero, no files on disk) on secret."""
    from repo_audit.render.renderer import render_and_write
    from repo_audit.schema.report import ScanReport, ReportMeta
    from datetime import date
    # Construct a ScanReport with the synthetic secret embedded in a tool_version field
    # (or wherever the renderer picks up text destined for the buffer).
    # The exact injection point is whatever Plan 04+05 expose for testing — for the stub,
    # we monkeypatch the markdown render to return a buffer containing the secret.
    from repo_audit.render import renderer as r
    monkeypatch.setattr(r, "render_markdown", lambda sr: f"## report\nleaked: {synthetic_secret}\n")
    sr = ScanReport(
        schema_version="1",
        meta=ReportMeta(repo_slug="x", commit_sha="0"*40, scan_date=date(2026, 5, 28), tool_version="0.1.0"),
        findings=[],
    )
    md = tmp_path / "report.md"
    js = tmp_path / "report.json"
    rc = render_and_write(sr, md, js)
    assert rc != 0
    assert not md.exists()
    assert not js.exists()


def test_diagnostic_redacts_secret_value(synthetic_secret):
    """D-06 — stderr diagnostic format is `file:line rule_id [REDACTED:<len>]`; never raw value."""
    from repo_audit.render.secret_lint import format_diagnostic, scan_with_entropy
    buf = f"line1\nline2 {synthetic_secret} tail\n"
    hits = scan_with_entropy(buf)
    diag = format_diagnostic(hits, buffer_name="markdown")
    assert "[REDACTED:" in diag
    assert synthetic_secret not in diag


def test_lint_runs_on_json_sidecar_buffer():
    """D-07 — secret-lint runs on JSON sidecar buffer (not just markdown)."""
    from repo_audit.render.secret_lint import lint_buffer, SecretsDetected
    # JSON shape containing a synthetic secret-like high-entropy literal in parsed_value.
    json_buf = '{"schema_version": "1", "evidence": {"output_snippet": "AKIAIOSFODNN7EXAMPLE"}}'
    with pytest.raises(SecretsDetected):
        lint_buffer(json_buf, buffer_name="json-sidecar")
