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
    """SkipReason Literal — only the locked values allowed.

    SCAN-BOUND-01 added an additive 7th member 'budget-truncated' (used by
    the walker caps, NOT by DEFAULT_SKIP_DIRS). DEFAULT_SKIP_DIRS itself
    still only uses the original six dir-classification reasons.
    """
    from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS
    allowed = {"vcs", "dependencies", "build-artifact", "cache", "editor", "test-output"}
    used = set(DEFAULT_SKIP_DIRS.values())
    assert used.issubset(allowed), f"unexpected SkipReason value: {used - allowed}"


def test_skipreason_includes_budget_truncated_additively():
    """SCAN-BOUND-01: 'budget-truncated' is a valid SkipReason; six originals kept."""
    import typing

    from repo_audit.walker.skip_dirs import SkipReason

    members = set(typing.get_args(SkipReason))
    assert "budget-truncated" in members
    assert {
        "vcs", "dependencies", "build-artifact", "cache", "editor", "test-output",
    }.issubset(members)


def test_walker_total_byte_cap_truncates_and_records_budget_truncated(
    tmp_path, monkeypatch,
):
    """SCAN-BOUND-01 / T-051-02: cumulative bytes over TOTAL_BYTE_CAP truncate.

    Uses a small monkeypatched cap so the test stays fast (no multi-GB
    fixtures). When the cap is crossed: status='partial', a
    (dir, 'budget-truncated') row is appended to skipped_dirs, and notes
    names where it truncated.
    """
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "byte-cap"
    repo.mkdir()
    # Three ~1KB files; cap at 1500 bytes forces truncation after file 2.
    for i in range(3):
        (repo / f"f{i}.py").write_text("x" * 1000, encoding="utf-8")
    monkeypatch.setattr(ri, "TOTAL_BYTE_CAP", 1500)

    result = ri.build_repo_index(repo)

    assert result.status == "partial"
    assert any(reason == "budget-truncated" for _, reason in result.skipped_dirs)
    assert result.notes  # non-empty, names where it truncated


def test_walker_depth_cap_prunes_and_records_budget_truncated(
    tmp_path, monkeypatch,
):
    """SCAN-BOUND-01 / T-051-02: traversal deeper than MAX_DEPTH is pruned."""
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "deep"
    repo.mkdir()
    # Build a chain repo/d0/d1/d2/d3 with a file at the deepest level.
    cur = repo
    for i in range(4):
        cur = cur / f"d{i}"
        cur.mkdir()
    (cur / "deep.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(ri, "MAX_DEPTH", 2)

    result = ri.build_repo_index(repo)

    assert any(reason == "budget-truncated" for _, reason in result.skipped_dirs)
    # The deepest file beyond MAX_DEPTH must not be indexed.
    assert all("deep.py" not in str(p) for p in result.index)


def test_walker_healthy_tree_stays_ok_no_budget_truncated(tmp_path):
    """SCAN-BOUND-01: a small healthy tree under all caps stays status='ok'."""
    from repo_audit.walker import build_repo_index

    repo = tmp_path / "healthy"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.ts").write_text("export const b = 2;\n", encoding="utf-8")
    sub = repo / "src"
    sub.mkdir()
    (sub / "c.py").write_text("y = 2\n", encoding="utf-8")

    result = build_repo_index(repo)

    assert result.status == "ok"
    assert all(reason != "budget-truncated" for _, reason in result.skipped_dirs)
