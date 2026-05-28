"""COLL-02 tests. Implementation lands in Plan 02-03."""


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
