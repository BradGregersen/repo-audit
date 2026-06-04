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


# --- CR-01: trusted_only mode for vendored/system SECURITY scanners --------
#
# CR-01 (12-SECURITY.md): when the vendored binary is ABSENT (any non-linux_amd64
# platform, or a removed binary), the default resolution ladder falls through to
# steps 1-2 (<scan_target>/node_modules/.bin and walk-up ancestors), where a
# HOSTILE target repo can plant a binary the scanner then executes with
# cwd=scan_target — arbitrary code execution. ``trusted_only=True`` closes this by
# restricting resolution to step 0 (vendored) + step 3 (PATH), never the target
# repo's node_modules. The npm PROJECT tools (tsc/eslint/knip/...) keep the default
# behavior — target-repo resolution is their intended T-03-03 PATH-hijack mitigation.


def test_trusted_only_skips_planted_target_node_modules(tmp_path, monkeypatch):
    """trusted_only=True: a planted ``<scan_target>/node_modules/.bin/syft`` is NOT exec'd.

    Vendored binary absent + tool present in the UNTRUSTED target repo's
    node_modules + nothing on PATH ⇒ resolution must return None (never the
    attacker-planted binary). This is the core CR-01 fix.
    """
    vendor_root = tmp_path / "vendor"
    vendor_root.mkdir()  # empty → vendored syft absent
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)
    monkeypatch.setenv("PATH", "")  # nothing trusted on PATH

    # Hostile target repo plants node_modules/.bin/syft.
    repo = tmp_path / "target"
    bin_dir = repo / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    planted = bin_dir / "syft"
    _make_executable(planted)

    # Default behavior WOULD return the planted binary; trusted_only must not.
    assert resolve_tool("syft", repo, trusted_only=True) is None


def test_trusted_only_skips_walk_up_ancestor_node_modules(tmp_path, monkeypatch):
    """trusted_only=True: a planted binary in a WALK-UP ancestor's node_modules is NOT exec'd."""
    import pygit2

    vendor_root = tmp_path / "vendor"
    vendor_root.mkdir()
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)
    monkeypatch.setenv("PATH", "")

    repo = tmp_path / "target"
    pygit2.init_repository(str(repo), bare=False)
    bin_dir = repo / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    planted = bin_dir / "osv-scanner"
    _make_executable(planted)
    nested = repo / "packages" / "app"
    nested.mkdir(parents=True)

    # Walk-up from the nested dir would find the planted ancestor binary;
    # trusted_only must skip both step 1 and step 2.
    assert resolve_tool("osv-scanner", nested, trusted_only=True) is None


def test_trusted_only_vendored_binary_still_wins(tmp_path, monkeypatch):
    """trusted_only=True: the vendored binary (step 0) is STILL returned when present."""
    vendor_root = tmp_path / "vendor"
    tool_dir = vendor_root / "grype"
    tool_dir.mkdir(parents=True)
    vendored = tool_dir / "grype"
    _make_executable(vendored)
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)

    # Plant a competing binary in the target repo to prove vendored wins.
    repo = tmp_path / "target"
    bin_dir = repo / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    _make_executable(bin_dir / "grype")

    assert resolve_tool("grype", repo, trusted_only=True) == vendored


def test_trusted_only_path_fallback_still_works(tmp_path, monkeypatch):
    """trusted_only=True: PATH (step 3) is STILL a valid fallback when vendored absent."""
    vendor_root = tmp_path / "vendor"
    vendor_root.mkdir()
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)

    path_dir = tmp_path / "pathbin"
    path_dir.mkdir()
    on_path = path_dir / "semgrep"
    _make_executable(on_path)
    monkeypatch.setenv("PATH", str(path_dir))

    repo = tmp_path / "target"
    repo.mkdir()
    resolved = resolve_tool("semgrep", repo, trusted_only=True)
    assert resolved == on_path


def test_default_still_resolves_target_node_modules(tmp_path, monkeypatch):
    """Regression: trusted_only=False (default) STILL resolves the target-repo binary.

    Pins the project-tool (tsc/eslint) behavior so the CR-01 fix cannot silently
    break the intended T-03-03 PATH-hijack mitigation.
    """
    vendor_root = tmp_path / "vendor"
    vendor_root.mkdir()  # vendored absent
    monkeypatch.setattr(resolution, "_VENDOR_ROOT", vendor_root)
    monkeypatch.setenv("PATH", "")

    repo = tmp_path / "target"
    bin_dir = repo / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    local = bin_dir / "tsc"
    _make_executable(local)

    # Default (no trusted_only) must still return the project-local binary.
    assert resolve_tool("tsc", repo) == local
