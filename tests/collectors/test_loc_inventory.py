"""COLL-02 tests. Implementation lands in Plan 02-03."""

import pytest


# real_subprocess: exercises the real vendored scc binary.
@pytest.mark.real_subprocess
def test_loc_inventory_emits_per_language_findings(fake_repo):
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n", "b.ts": "const b = 2;\n"}, name="loc-mix")
    result = run(repo, {})
    assert result.status == "ok"
    langs = {f.evidence.parsed_value.get("language") for f in result.findings}
    assert "Python" in langs or "TypeScript" in langs


def test_loc_inventory_strips_scc_Content_field(fake_repo):
    """Pitfall 1: base64 Content field must be stripped before findings construct."""
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n" * 100}, name="content-strip")
    result = run(repo, {})
    for f in result.findings:
        for k, v in f.evidence.parsed_value.items():
            if isinstance(v, str):
                assert "Content" not in k


def test_loc_inventory_missing_scc_binary_returns_unavailable(monkeypatch, fake_repo):
    from repo_audit.collectors import loc_inventory as li
    repo = fake_repo({"a.py": "x=1\n"}, name="no-scc")
    monkeypatch.setattr(li, "_scc_binary_path", lambda: __import__("pathlib").Path("/nonexistent/scc"))
    result = li.run(repo, {})
    assert result.status == "unavailable"


def test_loc_inventory_finding_source_tool_scc(fake_repo):
    """Every per-language finding emitted by COLL-02 carries source_tool='scc'."""
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n", "b.ts": "const b = 2;\n"}, name="src-tool")
    result = run(repo, {})
    if result.findings:
        for f in result.findings:
            assert f.source_tool == "scc"
            assert f.source_collector == "loc_inventory"
            assert f.dimension == "quality"


def test_loc_inventory_top_n_finding_present(fake_repo):
    """Top-N-largest aggregate Finding emits with 'top_files' parsed_value key."""
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n" * 50, "b.py": "x=1\n" * 30}, name="top-n")
    result = run(repo, {})
    top_findings = [f for f in result.findings
                    if "top_files" in f.evidence.parsed_value]
    assert len(top_findings) == 1
    top_files = top_findings[0].evidence.parsed_value["top_files"]
    assert isinstance(top_files, list)
    assert all(isinstance(d, dict) and "file" in d and "lines" in d for d in top_files)


def test_loc_inventory_platform_resolution_recognizes_linux(monkeypatch):
    """Platform resolver maps Linux + x86_64/aarch64 to linux-x86_64/linux-arm64."""
    from repo_audit.collectors.loc_inventory import _platform_tag
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    assert _platform_tag() == "linux-x86_64"
    monkeypatch.setattr("platform.machine", lambda: "aarch64")
    assert _platform_tag() == "linux-arm64"


def test_loc_inventory_platform_resolution_rejects_windows(monkeypatch):
    """Platform resolver raises RuntimeError for unsupported platforms (Windows per D-34)."""
    import pytest
    from repo_audit.collectors.loc_inventory import _platform_tag
    monkeypatch.setattr("platform.system", lambda: "Windows")
    with pytest.raises(RuntimeError, match="unsupported platform"):
        _platform_tag()


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_scc_argv_includes_exclude_dir_with_default_skip_dirs(
    monkeypatch, tmp_path,
):
    """SCAN-BOUND-01 (D-051-08): scc is invoked with --exclude-dir parity.

    The argv must carry --exclude-dir with the DEFAULT_SKIP_DIRS dir names
    (comma-separated) so scc cannot walk vendored/build trees even on a repo
    with a poor .gitignore. --no-gitignore must NOT be present (that would
    remove scc's own default protection). We capture the argv by stubbing
    subprocess.run; the binary-existence check is stubbed so the test runs
    on any platform without the vendored binary.
    """
    import subprocess

    from repo_audit.collectors import loc_inventory as li
    from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS

    repo = tmp_path / "scc-argv"
    repo.mkdir()
    # Point _scc_binary_path at a real file that exists() naturally — avoids
    # patching pathlib.Path.exists (which would leak across tests).
    fake_binary = tmp_path / "scc"
    fake_binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(li, "_scc_binary_path", lambda: fake_binary)

    captured = {}

    class _Result:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def fake_run(argv, *args, **kwargs):
        captured["argv"] = argv
        return _Result()

    monkeypatch.setattr(subprocess, "run", fake_run)
    li._run_scc(repo)

    argv = captured["argv"]
    assert "--exclude-dir" in argv
    idx = argv.index("--exclude-dir")
    exclude_arg = argv[idx + 1]
    # Every DEFAULT_SKIP_DIRS name is present in the comma-separated list.
    names = set(exclude_arg.split(","))
    assert set(DEFAULT_SKIP_DIRS).issubset(names)
    # --no-gitignore must NOT be present (keeps scc's default protection).
    assert "--no-gitignore" not in argv
