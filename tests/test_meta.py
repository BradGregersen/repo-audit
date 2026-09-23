"""Tests for repo_audit.meta — slug, head_sha, output paths.

Pinned by Plan 01-04 Task 1.
"""
from __future__ import annotations

import datetime as _dt
from datetime import date
from pathlib import Path

import pygit2
import pytest


# ---- repo_slug (D-16) ----

def test_slug_simple_lowercase():
    from repo_audit.meta.slug import repo_slug
    assert repo_slug(Path("/tmp/exampleapp")) == "exampleapp"


def test_slug_collapses_spaces_and_case():
    from repo_audit.meta.slug import repo_slug
    assert repo_slug(Path("/tmp/My Dashboard repo")) == "my-dashboard-repo"


def test_slug_preserves_existing_hyphens():
    from repo_audit.meta.slug import repo_slug
    assert repo_slug(Path("/tmp/my-client-fork")) == "my-client-fork"


# ---- head_sha (D-12, Pitfall 3) ----

def test_head_sha_raises_on_non_git_dir(tmp_path):
    from repo_audit.meta.git import NotAGitRepo, head_sha
    with pytest.raises(NotAGitRepo):
        head_sha(tmp_path)


def test_head_sha_uncommitted_marker_on_empty_repo(tmp_path):
    """Pitfall 3 — fresh `git init` with no commits returns the literal 'UNCOMMITTED'."""
    from repo_audit.meta.git import UNCOMMITTED_MARKER, head_sha
    pygit2.init_repository(str(tmp_path), bare=False)
    assert head_sha(tmp_path) == UNCOMMITTED_MARKER


def test_head_sha_returns_40char_hex_for_committed_repo(tmp_path):
    from repo_audit.meta.git import head_sha
    repo = pygit2.init_repository(str(tmp_path), bare=False)
    ts = int(_dt.datetime(2026, 5, 28, 12, 0, 0).timestamp())
    sig = pygit2.Signature("t", "t@e.com", ts, 0)
    tree = repo.TreeBuilder().write()
    repo.create_commit("HEAD", sig, sig, "init", tree, [])
    sha = head_sha(tmp_path)
    assert len(sha) == 40
    int(sha, 16)  # raises if not hex


# ---- state_report_paths (D-15 + Pitfall 4) ----

def test_state_report_paths_basic(tmp_path):
    from repo_audit.meta.paths import state_report_paths
    repo = tmp_path / "myrepo"
    repo.mkdir()
    md, js = state_report_paths(repo, date(2026, 5, 28))
    assert md == repo / "docs" / "state-reports" / "myrepo-state-report-2026-05-28.md"
    assert js == repo / "docs" / "state-reports" / "myrepo-state-report-2026-05-28.json"


def test_state_report_paths_does_not_create_directories(tmp_path):
    """D-15 + Pitfall 8 — paths helper is pure; mkdir happens later, after secret-lint."""
    from repo_audit.meta.paths import state_report_paths
    repo = tmp_path / "myrepo"
    repo.mkdir()
    state_report_paths(repo, date(2026, 5, 28))
    assert not (repo / "docs").exists()


def test_state_report_paths_collision_appends_suffix(tmp_path):
    """Pitfall 4 — second-run-same-day appends -2 instead of overwriting."""
    from repo_audit.meta.paths import state_report_paths
    repo = tmp_path / "myrepo"
    repo.mkdir()
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    (out_dir / "myrepo-state-report-2026-05-28.md").write_text("first")
    md, js = state_report_paths(repo, date(2026, 5, 28))
    assert md.name == "myrepo-state-report-2026-05-28-2.md"
    assert js.name == "myrepo-state-report-2026-05-28-2.json"


def test_state_report_paths_collision_appends_3_when_2_taken(tmp_path):
    from repo_audit.meta.paths import state_report_paths
    repo = tmp_path / "myrepo"
    repo.mkdir()
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True)
    (out_dir / "myrepo-state-report-2026-05-28.md").write_text("first")
    (out_dir / "myrepo-state-report-2026-05-28-2.md").write_text("second")
    md, _js = state_report_paths(repo, date(2026, 5, 28))
    assert md.name == "myrepo-state-report-2026-05-28-3.md"
