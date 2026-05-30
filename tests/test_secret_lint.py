"""Secret-lint chokepoint tests. Implementation lands in Plan 05 (Wave 2)."""
import pytest


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
    monkeypatch.setattr(
        r, "render_markdown", lambda sr, **kwargs: f"## report\nleaked: {synthetic_secret}\n"
    )
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


# --- SECRET-LINT-SPLIT-01 (Plan 05.1-02): render-local redact-and-continue ---
#
# A benign high-entropy token that is NOT a structured/known secret (e.g. a
# sha512- lockfile hash). >=4.5 bits/char Shannon entropy, >=5 chars, mixed
# alphabet, no AKIA/ghp_/sk_live_ prefix. Picked to deterministically trip the
# entropy backstop while NOT matching any KNOWN_PATTERN.
BENIGN_ENTROPY_TOKEN = "aB3xQ9zK7mP2wL5vR8tN4cF6yH1dG0sJ"


def _entropy_hits(text: str) -> int:
    """Count only entropy-backstop hits (ignore composed known-pattern hits)."""
    from repo_audit.render.secret_lint import scan_with_entropy

    return sum(1 for h in scan_with_entropy(text) if h.rule_id == "entropy-backstop")


def test_benign_token_is_entropy_only():
    """Guard: the test token trips the entropy backstop but is NOT a known pattern."""
    from repo_audit.render.secret_lint import (
        scan_with_known_patterns,
        shannon_entropy_bits_per_char,
        ENTROPY_THRESHOLD_BITS_PER_CHAR,
    )

    assert (
        shannon_entropy_bits_per_char(BENIGN_ENTROPY_TOKEN)
        >= ENTROPY_THRESHOLD_BITS_PER_CHAR
    )
    assert scan_with_known_patterns(BENIGN_ENTROPY_TOKEN) == []


def test_entropy_redact_and_continue():
    """D-051-02: entropy-only token → cleaned buffer + value-blind log, NO raise."""
    from repo_audit.render.secret_lint import lint_and_redact_entropy

    buf = f"line one\nhash: {BENIGN_ENTROPY_TOKEN}\nline three\n"
    cleaned, log = lint_and_redact_entropy(buf, buffer_name="markdown")

    # Token redacted in place; raw token gone from the cleaned buffer.
    assert BENIGN_ENTROPY_TOKEN not in cleaned
    assert f"[REDACTED:{len(BENIGN_ENTROPY_TOKEN)}]" in cleaned
    # Surrounding text preserved.
    assert "line one" in cleaned
    assert "line three" in cleaned
    assert "hash: " in cleaned

    # One value-blind log entry on line 2.
    assert len(log) == 1
    entry = log[0]
    assert entry == {
        "line": 2,
        "rule_id": "entropy-backstop",
        "redacted_len": len(BENIGN_ENTROPY_TOKEN),
    }


def test_known_pattern_hard_block(synthetic_secret):
    """D-051-01: a known-pattern secret (AKIA...) STILL hard-blocks (raise)."""
    from repo_audit.render.secret_lint import (
        lint_and_redact_entropy,
        SecretsDetected,
    )

    buf = f"normal text\nleaked: {synthetic_secret}\nmore text\n"
    with pytest.raises(SecretsDetected):
        lint_and_redact_entropy(buf, buffer_name="markdown")


def test_entropy_plus_known_still_blocks(synthetic_secret):
    """D-051: a buffer with BOTH an entropy token and a known-pattern token
    STILL raises — the entropy downgrade does NOT weaken the known slice
    (RESEARCH Pitfall 2)."""
    from repo_audit.render.secret_lint import (
        lint_and_redact_entropy,
        SecretsDetected,
    )

    buf = (
        f"benign hash: {BENIGN_ENTROPY_TOKEN}\n"
        f"real secret: {synthetic_secret}\n"
    )
    with pytest.raises(SecretsDetected):
        lint_and_redact_entropy(buf, buffer_name="markdown")


def test_no_reflag():
    """D-051 / RESEARCH Pitfall 3: re-scanning the cleaned buffer yields zero
    entropy-backstop hits — the [REDACTED:N] marker does not re-trip."""
    from repo_audit.render.secret_lint import lint_and_redact_entropy

    buf = f"a\n{BENIGN_ENTROPY_TOKEN}\nb\n"
    cleaned, log = lint_and_redact_entropy(buf, buffer_name="markdown")
    assert len(log) == 1
    assert _entropy_hits(cleaned) == 0


def test_redaction_log_value_blind():
    """D-051-02 / T-051-07: log entries never contain any substring of the
    original token — value-blind, only line/rule_id/redacted_len."""
    from repo_audit.render.secret_lint import lint_and_redact_entropy

    buf = f"x\n{BENIGN_ENTROPY_TOKEN}\n"
    _cleaned, log = lint_and_redact_entropy(buf, buffer_name="markdown")
    assert log
    for entry in log:
        assert set(entry.keys()) == {"line", "rule_id", "redacted_len"}
        # No field carries the raw token (or any non-trivial slice of it).
        for value in entry.values():
            assert str(value) not in BENIGN_ENTROPY_TOKEN or len(str(value)) <= 2


def test_multiple_entropy_tokens_one_line_redacted_right_to_left():
    """Two entropy tokens on one line both redact correctly (right-to-left span
    replace keeps earlier offsets valid)."""
    from repo_audit.render.secret_lint import lint_and_redact_entropy

    # Both >=4.5 bits/char (verified) and NOT known patterns, so each trips the
    # entropy backstop independently.
    t1 = "aB3xQ9zK7mP2wL5vR8tN4cF6yH1dG0sJ"
    t2 = "Zk7Wm2Qp9Lv4Rt8Nc3Fy6Hd1Gs0Jb5Xa"
    buf = f"both: {t1} and {t2} end\n"
    cleaned, log = lint_and_redact_entropy(buf, buffer_name="markdown")
    assert t1 not in cleaned
    assert t2 not in cleaned
    assert cleaned.count("[REDACTED:") == 2
    assert "both: " in cleaned and " and " in cleaned and " end" in cleaned
    assert len(log) == 2
    assert all(e["line"] == 1 for e in log)


def test_clean_buffer_unchanged_no_log():
    """A buffer with no entropy/known/gitleaks hits is returned unchanged with
    an empty log."""
    from repo_audit.render.secret_lint import lint_and_redact_entropy

    buf = "This is a normal report with words and small ints like 42 and 7.\n"
    cleaned, log = lint_and_redact_entropy(buf, buffer_name="markdown")
    assert cleaned == buf
    assert log == []


def test_entropy_redactions_field_on_report_meta():
    """schema/report.py: ReportMeta carries an additive entropy_redactions list
    defaulting to [] (schema_version stays '1')."""
    from datetime import date

    from repo_audit.schema.report import ReportMeta, ScanReport

    meta = ReportMeta(
        repo_slug="x",
        commit_sha="0" * 40,
        scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
    )
    assert meta.entropy_redactions == []
    sr = ScanReport(schema_version="1", meta=meta, findings=[])
    assert sr.schema_version == "1"
    # Round-trips through JSON as an empty list (forward-compat for fleet reader).
    assert '"entropy_redactions"' in sr.model_dump_json()
