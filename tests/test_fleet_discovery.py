"""Tests for repo_audit.fleet.discovery (FLEET-01, guards Pitfall 6).

Covers immediate-`.git`-children discovery, `.git`-as-FILE (worktree shape),
non-repo skipping, symlink refusal + recording, deterministic order, and the
no-recursion guarantee.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_audit.fleet.discovery import DiscoveryResult, discover_repos


def _make_git_dir_repo(parent: Path, name: str) -> Path:
    """A child dir whose `.git` is a DIRECTORY (normal repo shape)."""
    repo = parent / name
    (repo / ".git").mkdir(parents=True)
    return repo


def _make_git_file_repo(parent: Path, name: str) -> Path:
    """A child dir whose `.git` is a FILE (worktree/submodule shape)."""
    repo = parent / name
    repo.mkdir(parents=True)
    (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n", encoding="utf-8")
    return repo


def test_discovers_immediate_git_dir_and_file_children(tmp_path):
    """(a) two `.git`-dir repos + (b) one `.git`-FILE repo are all discovered."""
    _make_git_dir_repo(tmp_path, "alpha")
    _make_git_dir_repo(tmp_path, "bravo")
    _make_git_file_repo(tmp_path, "charlie-worktree")

    result = discover_repos(tmp_path)

    assert isinstance(result, DiscoveryResult)
    names = [p.name for p in result.repos]
    assert names == ["alpha", "bravo", "charlie-worktree"]


def test_skips_non_repo_dirs_silently(tmp_path):
    """(c) a plain dir with no `.git` is skipped, not errored."""
    _make_git_dir_repo(tmp_path, "real-repo")
    (tmp_path / "just-a-folder").mkdir()
    (tmp_path / "loose-file.txt").write_text("hi", encoding="utf-8")

    result = discover_repos(tmp_path)

    assert [p.name for p in result.repos] == ["real-repo"]
    assert result.skipped_symlinks == []


def test_symlinked_repo_skipped_and_recorded(tmp_path):
    """(d) a symlink pointing at a real repo is refused AND recorded (T-05-06)."""
    target = _make_git_dir_repo(tmp_path / "_outside", "target-repo")
    sweep = tmp_path / "sweep"
    sweep.mkdir()
    _make_git_dir_repo(sweep, "honest-repo")
    link = sweep / "linked-repo"
    link.symlink_to(target, target_is_directory=True)

    result = discover_repos(sweep)

    assert [p.name for p in result.repos] == ["honest-repo"]
    assert [p.name for p in result.skipped_symlinks] == ["linked-repo"]


def test_deterministic_order(tmp_path):
    """(e) discovery order is deterministic (sorted by name) regardless of fs order."""
    for name in ["zeta", "alpha", "mike", "bravo"]:
        _make_git_dir_repo(tmp_path, name)

    first = [p.name for p in discover_repos(tmp_path).repos]
    second = [p.name for p in discover_repos(tmp_path).repos]

    assert first == second == ["alpha", "bravo", "mike", "zeta"]


def test_does_not_recurse(tmp_path):
    """A repo nested INSIDE another repo's subdir is NOT discovered (no recursion)."""
    outer = _make_git_dir_repo(tmp_path, "outer")
    nested = outer / "vendor" / "nested-repo"
    (nested / ".git").mkdir(parents=True)

    result = discover_repos(tmp_path)

    assert [p.name for p in result.repos] == ["outer"]


def test_non_directory_root_raises(tmp_path):
    """A non-directory sweep root surfaces a clean NotADirectoryError."""
    f = tmp_path / "not-a-dir.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        discover_repos(f)


def test_seeded_repo_fixture_is_discovered(fake_repo):
    """A pygit2-seeded fake_repo (real `.git` dir) is discovered under its parent."""
    repo = fake_repo({"package.json": "{}"}, name="seeded")
    result = discover_repos(repo.parent)
    assert "seeded" in [p.name for p in result.repos]
