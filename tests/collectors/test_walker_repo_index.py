"""Walker (RepoIndex + skip-dirs) tests. STRICT — lands in Plan 02-01a."""
from pathlib import Path

from repo_audit.walker import build_repo_index, DEFAULT_SKIP_DIRS


def test_walker_indexes_repo_files(tmp_path):
    repo = tmp_path / "small"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.md").write_text("# x\n", encoding="utf-8")
    result = build_repo_index(repo)
    assert result.status == "ok"
    paths = {p.name for p in result.index}
    assert paths == {"a.py", "b.md"}


def test_walker_records_filemeta(tmp_path):
    repo = tmp_path / "meta"
    repo.mkdir()
    f = repo / "x.ts"
    content = "export const x = 1;\n"
    f.write_text(content, encoding="utf-8")
    result = build_repo_index(repo)
    meta = next(iter(result.index.values()))
    assert meta.size_bytes == len(content.encode("utf-8"))
    assert meta.ext == ".ts"
    assert meta.path == f.resolve() or meta.path == f


def test_walker_skips_default_dirs_auto_logged(skipped_dir_repo):
    result = build_repo_index(skipped_dir_repo)
    # node_modules contents NOT in index
    assert all("node_modules" not in str(p) for p in result.index)
    # skipped_dirs auto-logged with reason='dependencies'
    reasons = {reason for _, reason in result.skipped_dirs}
    assert "dependencies" in reasons


def test_walker_does_not_follow_symlinks(tmp_path):
    repo = tmp_path / "sym"
    repo.mkdir()
    (repo / "real.txt").write_text("x\n", encoding="utf-8")
    # Cyclic symlink: link → repo itself
    try:
        (repo / "loop").symlink_to(repo)
    except OSError:
        import pytest
        pytest.skip("symlink creation not supported on this filesystem")
    result = build_repo_index(repo)
    # real.txt should be indexed; no recursion through loop
    assert any(p.name == "real.txt" for p in result.index)
    # status should be 'ok' (not partial — far below 200k cap)
    assert result.status == "ok"


def test_walker_excludes_docs_state_reports(tmp_path):
    """Pitfall 7: docs/state-reports/ is the tool's own output; excluded from index."""
    repo = tmp_path / "self-output"
    repo.mkdir()
    sr = repo / "docs" / "state-reports"
    sr.mkdir(parents=True)
    (sr / "yesterday.md").write_text("# old\n", encoding="utf-8")
    (repo / "src.py").write_text("x = 1\n", encoding="utf-8")
    result = build_repo_index(repo)
    # yesterday.md NOT in index
    assert all("state-reports" not in str(p) for p in result.index)
    # src.py IS in index
    assert any(p.name == "src.py" for p in result.index)


def test_walker_skipped_dirs_use_only_locked_reason_literals():
    """SkipReason Literal — only the six values allowed."""
    from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS
    allowed = {"vcs", "dependencies", "build-artifact", "cache", "editor", "test-output"}
    used = set(DEFAULT_SKIP_DIRS.values())
    assert used.issubset(allowed), f"unexpected SkipReason value: {used - allowed}"
