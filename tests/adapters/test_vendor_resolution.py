"""D-06-10 — vendor/ resolution step is prepended to ``resolve_tool``.

Vendored static binaries (first one arrives with osv-scanner in Phase 7) live
in-package at ``src/repo_audit/vendor/<tool>/<tool>`` — the same location
CLAUDE.md uses for vendored ``scc``. When such a file exists it is the
highest-priority resolution hit, ahead of the project-local node_modules
walk-up and the PATH fallback (because we control the vendored binary; PATH and
target-repo shims are less trusted — T-06-03).

The ``vendor/`` dir does not exist yet; these tests monkeypatch the vendor root
so the resolution PATH is exercised without committing a binary, and prove the
new step is ADDITIVE (clean fall-through when absent — T-03-03 walk-up + PATH
fallback unchanged).
"""
from __future__ import annotations

import os
import stat

import pytest

from repo_audit.adapters import resolution
from repo_audit.adapters.resolution import _vendor_binary, resolve_tool


def _make_executable(path):
    path.write_text("#!/bin/sh\necho stub\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_vendor_binary_wins_over_path(tmp_path, monkeypatch):
    """A vendored ``<tool>/<tool>`` is returned even when PATH would resolve it."""
    # Lay down a fake vendor root: <vendor>/sometool/sometool (executable).
    vendor_root = tmp_path / "vendor"
    tool_dir = vendor_root / "sometool"
    tool_dir.mkdir(parents=True)
    vendored = tool_dir / "sometool"
    _make_executable(vendored)

    # Also make the SAME tool resolvable on PATH, to prove vendor wins.
    path_dir = tmp_path / "pathbin"
    path_dir.mkdir()
    on_path = path_dir / "sometool"
    _make_executable(on_path)
    monkeypatch.setenv("PATH", str(path_dir))

    # Point the resolver's vendor root at our fake tree.
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)

    empty_repo = tmp_path / "repo"
    empty_repo.mkdir()
    resolved = resolve_tool("sometool", empty_repo)
    assert resolved == vendored, "vendor/ hit must win over PATH"


def test_missing_vendor_dir_falls_through_to_path(tmp_path, monkeypatch):
    """No vendor file present ⇒ resolve_tool still returns the PATH result."""
    # Vendor root points at a dir with no matching tool → miss.
    vendor_root = tmp_path / "vendor"
    vendor_root.mkdir()
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)

    path_dir = tmp_path / "pathbin"
    path_dir.mkdir()
    on_path = path_dir / "tsc"
    _make_executable(on_path)
    monkeypatch.setenv("PATH", str(path_dir))

    empty_repo = tmp_path / "repo"
    empty_repo.mkdir()
    resolved = resolve_tool("tsc", empty_repo)
    assert resolved is not None
    assert resolved.name == "tsc"
    # Specifically the PATH copy, not a vendored one (which doesn't exist).
    assert resolved == on_path


def test_vendor_binary_helper_returns_none_when_absent(tmp_path, monkeypatch):
    """``_vendor_binary`` returns None for an unvendored tool (greppable seam)."""
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", tmp_path / "vendor")
    assert _vendor_binary("not-vendored") is None


def test_vendor_root_is_in_package(tmp_path):
    """The default vendor root lives in-package next to the resolution module."""
    # src/repo_audit/vendor — same in-package location as vendored scc.
    assert resolution._VENDOR_ROOT.name == "vendor"
    assert resolution._VENDOR_ROOT.parent.name == "repo_audit"


def test_vendor_directory_not_a_file_falls_through(tmp_path, monkeypatch):
    """A vendor path that is a DIRECTORY (not a file) must not resolve."""
    vendor_root = tmp_path / "vendor"
    # Create <vendor>/weird/weird AS A DIRECTORY, not an executable file.
    (vendor_root / "weird" / "weird").mkdir(parents=True)
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)
    monkeypatch.setenv("PATH", "")
    repo = tmp_path / "repo"
    repo.mkdir()
    # No PATH, no node_modules, vendor is a dir → None (not the directory).
    assert resolve_tool("weird", repo) is None
