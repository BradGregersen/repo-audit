"""CLI integration tests. Implementation lands in Plan 06 (Wave 3)."""


def test_help_lists_all_subcommands(runner):
    """SC-1 / CLI-01 — `repo-audit --help` lists scan/detect/fleet."""
    from repo_audit.cli import app
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "detect" in result.stdout
    assert "fleet" in result.stdout


def test_bare_arch_prints_help(runner):
    """D-13 — bare `arch` (no subcommand) prints help, not an error."""
    from repo_audit.cli import app
    result = runner.invoke(app, [])
    # Typer's no_args_is_help=True exits with code 0 OR 2 depending on version;
    # what matters: stdout/stderr contains usage info, not an unhandled crash.
    assert "Usage" in (result.stdout + result.stderr)


def test_detect_command_lists_stacks(runner, polyglot_repo):
    """SC-2 / CLI-04 — `repo-audit detect <repo>` prints detected stacks with root dirs."""
    from repo_audit.cli import app
    result = runner.invoke(app, ["detect", str(polyglot_repo)])
    assert result.exit_code == 0
    assert "typescript-node" in result.stdout
    assert "supabase" in result.stdout


def test_scan_explicit_path(runner, fake_repo, tmp_path):
    """SC-3 / CLI-02 — `repo-audit scan <path>` writes report and sidecar."""
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="scan-target")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    # The slug is "scan-target"; date is whatever today is.
    reports_dir = repo / "docs" / "state-reports"
    md_files = list(reports_dir.glob("scan-target-state-report-*.md"))
    json_files = list(reports_dir.glob("scan-target-state-report-*.json"))
    assert len(md_files) == 1
    assert len(json_files) == 1


def test_scan_cwd_default(runner, fake_repo, monkeypatch):
    """D-14 / CLI-02 — `repo-audit scan` with no path defaults to cwd."""
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="cwd-target")
    monkeypatch.chdir(repo)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert (repo / "docs" / "state-reports").exists()


def test_self_test_secret_lint(runner):
    """D-08 / REP-05 — `repo-audit --doctor --self-test-secret-lint` exits non-zero with [REDACTED:."""
    from repo_audit.cli import app
    result = runner.invoke(app, ["--doctor", "--self-test-secret-lint"])
    assert result.exit_code != 0
    # The synthetic secret value MUST NOT appear in stderr; only the [REDACTED:N] marker may.
    assert "[REDACTED:" in result.stderr
    # AKIAIOSFODNN7EXAMPLE is the synthetic — assert the redaction worked:
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stderr
