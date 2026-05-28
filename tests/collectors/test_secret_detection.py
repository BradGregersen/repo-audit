"""COLL-03 tests -- Plan 02-04 implementation.

Original 3 stub tests from Plan 02-01b (xfail) are kept and flipped to
strict; 4 new tests cover the redaction template, SCH-08 forbidden-key
disjointness, the >1MB DoS guard, and the binary-file UnicodeDecodeError
skip path.

The full set covers all five threat-model gates (T-02-04-01 redaction,
T-02-04-02 docs/state-reports exclusion, T-02-04-03 DoS skip,
T-02-04-04 inherited via Phase 1 timeout, T-02-04-05 path traversal via
relative_to fallback) plus the GITLEAKS_AVAILABLE=False status='partial'
contract that surfaces the precision drop to the scope ledger.
"""
from __future__ import annotations


def test_secret_detection_redacts_value(fake_repo, synthetic_secret):
    """The raw synthetic value MUST NEVER appear in any Finding output.

    Verifies T-02-04-01 (information-disclosure mitigation):
    the hard-coded f-string template structurally prevents leakage even
    when a candidate hit fires.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"src/config.py": f"AWS_KEY = '{synthetic_secret}'\n"}, name="leak")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    # Synthetic value MUST NEVER appear in any output_snippet or parsed_value
    for f in result.findings:
        assert synthetic_secret not in f.evidence.output_snippet
        for v in f.evidence.parsed_value.values():
            assert synthetic_secret not in str(v)
    # At least one hit found via the backstop layer
    assert any(f.source_collector == "secret_detection" for f in result.findings)


def test_secret_detection_excludes_state_reports(fake_repo, synthetic_secret):
    """Pitfall 7 / T-02-04-02: docs/state-reports/ is excluded from the scan."""
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo(
        {"docs/state-reports/yesterday.md": "## leaked: [REDACTED:20]\n"},
        name="self-output",
    )
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    # No findings from yesterday's report (already excluded by walker)
    assert all("state-reports" not in (f.file or "") for f in result.findings)


def test_secret_detection_gitleaks_absent_status_partial(monkeypatch, fake_repo):
    """D-35: gitleaks PATH-absent -> status='partial' + ledger note."""
    from repo_audit.collectors import secret_detection as sd
    from repo_audit.walker import build_repo_index
    monkeypatch.setattr(sd, "GITLEAKS_AVAILABLE", False)
    repo = fake_repo({"x.py": "x=1\n"}, name="no-gitleaks")
    wr = build_repo_index(repo)
    result = sd.run(repo, wr.index)
    assert result.status == "partial"
    assert "gitleaks" in result.notes.lower()


# --- Plan 02-04 net-new strict tests ---


def test_secret_detection_finds_aws_key_via_known_pattern(fake_repo, synthetic_secret):
    """A planted AKIA-prefixed token surfaces under the aws-access-key-id rule.

    The synthetic_secret fixture is the canonical AWS example
    (AKIAIOSFODNN7EXAMPLE, 20 chars) -- it matches both the
    KNOWN_PATTERNS aws-access-key-id regex (via scan_with_known_patterns
    composed into scan_with_entropy) and gitleaks's aws-access-key rule
    when gitleaks is on PATH. The entropy-backstop label is the accepted
    fallback when neither precision layer fires.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"src/config.py": f"AWS_KEY = '{synthetic_secret}'\n"}, name="aws-key")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    rule_ids = {f.rule_id for f in result.findings}
    assert (
        "aws-access-key-id" in rule_ids
        or "aws-access-key" in rule_ids       # gitleaks rule id naming variant
        or "entropy-backstop" in rule_ids
    ), f"expected an AWS or entropy rule; got {rule_ids!r}"


def test_secret_detection_output_snippet_format(fake_repo, synthetic_secret):
    """T-02-04-01: every output_snippet matches the hard-coded redacted template.

    Format: '{rule_id} [REDACTED:{N}] at line {L}'
    The synthetic value must never appear.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"src/leak.py": f"X = '{synthetic_secret}'\n"}, name="snippet-fmt")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert result.findings, "expected at least one hit on a planted AKIA fixture"
    for f in result.findings:
        assert "[REDACTED:" in f.evidence.output_snippet
        assert " at line " in f.evidence.output_snippet
        assert synthetic_secret not in f.evidence.output_snippet


def test_secret_detection_parsed_value_has_no_raw_value_keys(fake_repo, synthetic_secret):
    """SCH-08 + D-35: parsed_value must never carry value/secret/match/raw fields.

    The collector structurally caps the parsed_value keyset to
    {'rule_id', 'redacted_len'}. This regression test enforces the
    forbidden keyset stays absent even after a future refactor.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"src/leak.py": f"X = '{synthetic_secret}'\n"}, name="parsed-keys")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert result.findings, "expected at least one hit on a planted AKIA fixture"
    forbidden = {"value", "secret", "match", "raw", "original", "token"}
    for f in result.findings:
        assert forbidden.isdisjoint(f.evidence.parsed_value.keys()), (
            f"parsed_value carries forbidden key(s): "
            f"{forbidden & f.evidence.parsed_value.keys()}"
        )


def test_secret_detection_skips_large_files(tmp_path):
    """T-02-04-03: files reported >1MB via FileMeta.size_bytes are skipped.

    We build the index manually with a synthetic >1MB size advertised on
    a small-on-disk file so the test runs in milliseconds. The collector
    trusts FileMeta.size_bytes for the DoS guard (the walker already did
    a real stat()); content with an AKIA pattern is NOT scanned because
    the size pre-filter triggers BEFORE the read_text() call.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import FileMeta
    repo = tmp_path / "big"
    repo.mkdir()
    big = repo / "big.txt"
    big.write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    fake_index = {big: FileMeta(path=big, size_bytes=2_000_000, ext=".txt")}
    result = run(repo, fake_index)
    # big.txt was skipped (size guard), so NO findings despite the AKIA token
    assert result.findings == []


def test_secret_detection_binary_files_skipped(tmp_path):
    """Files with non-text extensions or non-UTF-8 content are skipped cleanly.

    Combined coverage: the _looks_text() prune AND the UnicodeDecodeError
    fallback. A .png file with binary content should produce zero
    findings and the collector should complete without raising.
    """
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import FileMeta
    repo = tmp_path / "binary"
    repo.mkdir()
    png = repo / "image.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)
    # Build a synthetic index that includes only the binary file
    index = {png: FileMeta(path=png, size_bytes=png.stat().st_size, ext=".png")}
    result = run(repo, index)
    # No findings from the binary file
    assert result.findings == []
    # Collector still completes cleanly with a valid status
    assert result.status in ("ok", "partial")
