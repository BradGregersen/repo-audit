"""Phase 3 Wave 1 contract — SKIP via importorskip until plan 03-02 lands.

D-45 tool resolution: project-local node_modules/.bin/ wins, then walk-up
to git root, then PATH fallback via ``shutil.which``.
"""
from __future__ import annotations

import os
import stat

import pytest

pytest.importorskip(
    "repo_audit.adapters.resolution",
    reason="Wave 1 (plan 03-02) not yet landed — adapters.resolution missing",
)

from repo_audit.adapters.resolution import resolve_tool  # noqa: E402


def _make_executable(path):
    path.write_text("#!/bin/sh\necho stub\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_project_local_tool_resolution(tmp_path):
    """D-45 phase 1: ``<repo>/node_modules/.bin/<tool>`` is the first lookup."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    tsc = bin_dir / "tsc"
    _make_executable(tsc)
    resolved = resolve_tool("tsc", tmp_path)
    assert resolved == tsc


def test_walk_up_to_git_root(tmp_path):
    """D-45 phase 2: when ``<cwd>/node_modules/.bin/<tool>`` is absent, walk up to git root."""
    import pygit2
    pygit2.init_repository(str(tmp_path), bare=False)
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    tsc = bin_dir / "tsc"
    _make_executable(tsc)
    nested = tmp_path / "packages" / "app"
    nested.mkdir(parents=True)
    resolved = resolve_tool("tsc", nested)
    assert resolved == tsc


def test_path_fallback(tmp_path, monkeypatch):
    """D-45 phase 3: no project-local tool ⇒ fall back to ``shutil.which``."""
    fake_bin = tmp_path / "fake_path"
    fake_bin.mkdir()
    tsc = fake_bin / "tsc"
    _make_executable(tsc)
    monkeypatch.setenv("PATH", str(fake_bin))
    # repo without any node_modules
    empty_repo = tmp_path / "empty"
    empty_repo.mkdir()
    resolved = resolve_tool("tsc", empty_repo)
    assert resolved is not None
    assert resolved.name == "tsc"


def test_tool_not_found_returns_none(tmp_path, monkeypatch):
    """No project-local, no PATH match ⇒ ``None`` (adapter emits unavailable)."""
    monkeypatch.setenv("PATH", "")
    resolved = resolve_tool("definitely-not-a-real-tool-xyz", tmp_path)
    assert resolved is None
