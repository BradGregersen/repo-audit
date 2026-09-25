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


# --- 260530-gm9: entropy backstop is OPT-IN (default OFF) ---

# High-entropy content with NO known-pattern secret shape: an npm lockfile
# integrity hash line + a Shields.io badge URL with a high-entropy token.
# Verified during planning to trip the entropy-backstop (>=4.5 bits/char on a
# >=5-char token) while matching NO KNOWN_PATTERNS rule.
_HIGH_ENTROPY_NO_KNOWN_PATTERN = (
    '  "integrity": '
    '"sha512-MV0Yl1f0udeNJUYI3DjbsbWcA3M7q3a3i3a3+abcDEFghijKLMNop'
    'QRstuvWXyz0123456789ABCDEFGHIJKLMNOPqrstuvwxyz==",\n'
    "[![coverage](https://img.shields.io/badge/coverage-87%25-brightgreen"
    "?logo=jest&t=aB3xYz9KqWeRtY7uIoP1234567890qPzMnBvCxLkJhGfDsA)]"
    "(https://example.com)\n"
)


def test_entropy_backstop_off_by_default_zero_entropy_findings(fake_repo):
    """Default scan (no config) yields ZERO entropy-backstop findings on a
    high-entropy file (npm integrity hash + Shields badge URL)."""
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo(
        {"package-lock.json": _HIGH_ENTROPY_NO_KNOWN_PATTERN}, name="entropy-default-off"
    )
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert all(f.rule_id != "entropy-backstop" for f in result.findings), (
        "entropy backstop must be OFF by default: "
        f"{[f.rule_id for f in result.findings]!r}"
    )


def test_known_pattern_still_fires_by_default(fake_repo):
    """Default scan still flags a seeded real AKIA<16 alnum> token via the
    known-pattern rule (NOT via entropy)."""
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    # AKIA + 16 uppercase-alnum chars (distinct from the AKIA...EXAMPLE fixture).
    seeded = "AKIA" + "QWERTYUIOPASDFGH"
    repo = fake_repo(
        {"src/aws.py": f"AWS_ACCESS_KEY_ID = '{seeded}'\n"},
        name="known-pattern-default-on",
    )
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    rule_ids = {f.rule_id for f in result.findings}
    assert "aws-access-key-id" in rule_ids, (
        f"known-pattern detection must stay always-on; got {rule_ids!r}"
    )
    assert seeded not in "".join(f.evidence.output_snippet for f in result.findings)


def test_entropy_backstop_reappears_when_opted_in(fake_repo):
    """With secret_detection.entropy_backstop: true in the target repo's
    .repo-audit.yaml, entropy-backstop findings reappear."""
    from repo_audit.collectors.secret_detection import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo(
        {
            "package-lock.json": _HIGH_ENTROPY_NO_KNOWN_PATTERN,
            ".repo-audit.yaml": (
                "secret_detection:\n  entropy_backstop: true\n"
            ),
        },
        name="entropy-opt-in",
    )
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert any(f.rule_id == "entropy-backstop" for f in result.findings), (
        "opt-in flag must re-enable the entropy backstop: "
        f"{[f.rule_id for f in result.findings]!r}"
    )


# --- Phase 12 Plan 01 Task 1: per-scanner SecretHit.source attribution ---


def test_known_pattern_hit_carries_in_process_source():
    """scan_with_known_patterns stamps source='in-process' on every hit."""
    from repo_audit.render.secret_lint import scan_with_known_patterns

    hits = scan_with_known_patterns("KEY = 'AKIA" + "QWERTYUIOPASDFGH'\n")
    assert hits, "expected a known-pattern AKIA hit"
    assert all(h.source == "in-process" for h in hits), (
        f"known-pattern hits must be 'in-process'; got "
        f"{[h.source for h in hits]!r}"
    )


def test_entropy_hit_carries_in_process_source():
    """scan_with_entropy stamps source='in-process' on its entropy-backstop hits."""
    from repo_audit.render.secret_lint import scan_with_entropy

    hits = [h for h in scan_with_entropy(_HIGH_ENTROPY_NO_KNOWN_PATTERN)
            if h.rule_id == "entropy-backstop"]
    assert hits, "expected at least one entropy-backstop hit"
    assert all(h.source == "in-process" for h in hits), (
        f"entropy hits must be 'in-process'; got {[h.source for h in hits]!r}"
    )


def test_secret_detection_source_tool_is_per_hit_not_blanket(monkeypatch, fake_repo):
    """Folded Pitfall 4: an entropy-backstop hit is NEVER labeled 'gitleaks'.

    With gitleaks 'available' (so the old blanket stamp would have labeled
    everything 'gitleaks') but the gitleaks subprocess returning NO hits, the
    only findings come from the in-process backstop and must carry the
    producing scanner's label on BOTH source_tool and evidence.tool.
    """
    from repo_audit.collectors import secret_detection as sd
    from repo_audit.walker import build_repo_index

    # Pretend gitleaks is on PATH so the blanket-stamp bug (if present) would
    # mislabel every in-process hit as 'gitleaks'...
    monkeypatch.setattr(sd, "GITLEAKS_AVAILABLE", True)
    # ...but make the gitleaks dir/stdin scan find nothing, so all hits are
    # in-process.
    monkeypatch.setattr(sd, "scan_with_gitleaks", lambda *a, **k: [])
    monkeypatch.setattr(
        sd.secret_lint_mod, "scan_working_tree", lambda *a, **k: []
    )

    repo = fake_repo(
        {
            "package-lock.json": _HIGH_ENTROPY_NO_KNOWN_PATTERN,
            ".repo-audit.yaml": (
                "secret_detection:\n  entropy_backstop: true\n"
            ),
        },
        name="per-hit-source",
    )
    wr = build_repo_index(repo)
    result = sd.run(repo, wr.index)
    entropy_findings = [f for f in result.findings if f.rule_id == "entropy-backstop"]
    assert entropy_findings, "expected entropy-backstop findings"
    for f in entropy_findings:
        assert f.source_tool == "in-process", (
            f"entropy hit mislabeled: source_tool={f.source_tool!r}"
        )
        assert f.evidence.tool == "in-process", (
            f"entropy hit mislabeled: evidence.tool={f.evidence.tool!r}"
        )


# --- Phase 12 Plan 01 Task 1: scan_git_history value-blind sibling ---


_GITLEAKS_HISTORY_JSON = (
    '[{"RuleID": "aws-access-key", "File": "old/config.py", '
    '"StartLine": 7, "StartColumn": 11, "EndColumn": 31, '
    '"Secret": "REDACTED", "Commit": "abc123"}]'
)


def test_scan_git_history_redacts_and_uses_column_span(fp, tmp_path, monkeypatch):
    """scan_git_history points gitleaks at a repo, parses JSON, derives
    redacted_len from EndColumn-StartColumn, stamps source='gitleaks-history',
    and stores NO raw value."""
    from pathlib import Path

    from repo_audit.render import secret_lint

    repo = tmp_path / "histrepo"
    repo.mkdir()

    # ``fp`` fakes the spawn, but discovery runs first: make gitleaks look
    # installed so the test does not depend on the host PATH.
    real_which = secret_lint.shutil.which

    def _which(name, *args, **kwargs):
        if name == "gitleaks":
            return "/usr/local/bin/gitleaks"
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(secret_lint.shutil, "which", _which)

    # The implementation writes the JSON report to a tempfile and reads it back
    # (A3). Mock gitleaks to write that report to whichever --report-path it is
    # given.
    def _fake_gitleaks(process):
        argv = process.args
        # locate the --report-path value
        report_path = None
        for i, tok in enumerate(argv):
            if tok in ("--report-path", "-r"):
                report_path = argv[i + 1]
        if report_path and report_path != "-":
            Path(report_path).write_text(_GITLEAKS_HISTORY_JSON, encoding="utf-8")

    fp.register(
        ["gitleaks", "git", fp.any()],
        callback=_fake_gitleaks,
        returncode=1,  # gitleaks exits 1 when it finds secrets
    )

    hits = secret_lint.scan_git_history(repo, timeout=30)
    assert hits, "expected one history hit from the canned gitleaks JSON"
    h = hits[0]
    assert h.source == "gitleaks-history"
    assert h.redacted_len == 31 - 11  # EndColumn - StartColumn
    assert h.line == 7
    # value-blind: SecretHit carries no raw-value field
    assert not any(
        attr in vars(h) for attr in ("value", "secret", "raw", "match")
    )


def test_scan_git_history_absent_gitleaks_returns_empty(monkeypatch, tmp_path):
    """No gitleaks on PATH -> [] (Wave-1 collector maps absence to unavailable)."""
    from repo_audit.render import secret_lint

    monkeypatch.setattr(secret_lint.shutil, "which", lambda name: None)
    repo = tmp_path / "r"
    repo.mkdir()
    assert secret_lint.scan_git_history(repo, timeout=30) == []
