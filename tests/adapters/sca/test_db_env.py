"""Task 1 (Plan 07-05): persistent vuln-DB cache env (db_env.py).

These tests pin the RESEARCH Open-Q2 tension resolution: the vuln DB dirs must
escape the per-scan tempdir XDG redirect that ``build_scan_env`` injects, and
live on a STABLE persistent path resolved from the REAL user environment. They
also pin ``parse_grype_db_status`` against the recorded fixture.
"""
from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import pytest

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.sca.db_env import (
    build_sca_env,
    parse_grype_db_status,
    sca_db_dir,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "grype"


def test_sca_db_dir_is_stable_persistent_path(monkeypatch, tmp_path):
    """sca_db_dir resolves under the REAL user cache and is created."""
    fake_cache = tmp_path / "real-cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(fake_cache))
    db_dir = sca_db_dir()
    assert db_dir == fake_cache / "repo-audit" / "vuln-db"
    assert db_dir.is_dir()  # created


def test_sca_db_dir_falls_back_to_home_cache(monkeypatch, tmp_path):
    """No XDG_CACHE_HOME → ~/.cache/repo-audit/vuln-db."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    db_dir = sca_db_dir()
    assert db_dir == tmp_path / "home" / ".cache" / "repo-audit" / "vuln-db"
    assert db_dir.is_dir()


def test_build_sca_env_sets_the_four_db_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "real-cache"))
    env = build_sca_env({"PATH": "/usr/bin"})
    assert env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"].endswith("/vuln-db/osv")
    assert env["GRYPE_DB_CACHE_DIR"].endswith("/vuln-db/grype")
    assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert env["GRYPE_DB_VALIDATE_AGE"] == "false"
    # base_env carried through, not mutated.
    assert env["PATH"] == "/usr/bin"


def test_build_sca_env_does_not_mutate_base(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "real-cache"))
    base = {"PATH": "/usr/bin"}
    build_sca_env(base)
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" not in base


def test_db_dirs_escape_the_tempdir_redirect(monkeypatch, tmp_path):
    """The DB dirs must NOT live inside build_scan_env's per-scan tempdir.

    This is the Open-Q2 invariant: build_scan_env redirects XDG_CACHE_HOME to a
    throwaway tempdir, but the pinned DB must persist across scans. build_sca_env
    layered on top must point the two DB dirs at the STABLE path, escaping the
    redirect.
    """
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "persistent-cache"))
    with scan_tempdir() as td:
        base_env = build_scan_env(td)
        # build_scan_env redirected XDG_CACHE_HOME into the tempdir.
        assert base_env["XDG_CACHE_HOME"].startswith(str(td))
        sca_env = build_sca_env(base_env)
        osv_db = sca_env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]
        grype_db = sca_env["GRYPE_DB_CACHE_DIR"]
        # The DB dirs are NOT inside the per-scan tempdir.
        assert not osv_db.startswith(str(td))
        assert not grype_db.startswith(str(td))
        # And they are subdirs created on disk.
        assert Path(osv_db).is_dir()
        assert Path(grype_db).is_dir()


def test_parse_grype_db_status_returns_built_date():
    text = (_FIXTURES / "db-status.txt").read_text(encoding="utf-8")
    snapshot_date, advisory_count = parse_grype_db_status(text)
    assert snapshot_date == date(2026, 6, 1)
    # The recorded db-status.txt exposes no record count → None (never invented).
    assert advisory_count is None


def test_parse_grype_db_status_absent_built_returns_none():
    snapshot_date, advisory_count = parse_grype_db_status("Status: valid\n")
    assert snapshot_date is None
    assert advisory_count is None
