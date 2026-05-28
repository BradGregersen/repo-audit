"""COLL-03 tests. STUB — implementation lands in Plan 02-04."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-04 implements secret_detection")


def test_secret_detection_redacts_value(fake_repo, synthetic_secret):
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
    """Pitfall 7: docs/state-reports/ is excluded from the scan."""
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
    from repo_audit.collectors import secret_detection as sd
    from repo_audit.walker import build_repo_index
    monkeypatch.setattr(sd, "GITLEAKS_AVAILABLE", False)
    repo = fake_repo({"x.py": "x=1\n"}, name="no-gitleaks")
    wr = build_repo_index(repo)
    result = sd.run(repo, wr.index)
    assert result.status == "partial"
    assert "gitleaks" in result.notes.lower()
