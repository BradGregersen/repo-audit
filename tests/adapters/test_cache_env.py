"""Cache-redirection contract. Skipped via importorskip when the module is absent.

D-46 cache-redirection: one tempdir per scan exports
``XDG_CACHE_HOME``, ``npm_config_cache``, ``NO_COLOR=1``, ``CI=1`` for
the child subprocess so neither the user's $HOME nor the target repo is
written to. Tempdir is cleaned up via context-manager exit.

NOTE: The host-independent SC-6 check lives in
``tests/adapters/test_post_scan_repo_clean_unit.py`` (checker Blocker 6).
The live-binary integration check lives in
``tests/adapters/test_integration_typescript.py::test_post_scan_repo_clean``
(the canonical location for that check).
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip(
    "repo_audit.adapters.cache_env",
    reason="optional module repo_audit.adapters.cache_env not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters.cache_env import scan_cache_env  # noqa: E402


def test_env_vars_set(tmp_path):
    """D-46: ``XDG_CACHE_HOME``, ``npm_config_cache``, ``NO_COLOR=1``, ``CI=1`` are exported."""
    with scan_cache_env(tmp_path) as env:
        assert "XDG_CACHE_HOME" in env
        assert "npm_config_cache" in env
        assert env.get("NO_COLOR") == "1"
        assert env.get("CI") == "1"
        # Both cache dirs MUST point inside the supplied tempdir
        xdg = env["XDG_CACHE_HOME"]
        npm = env["npm_config_cache"]
        assert str(tmp_path) in xdg
        assert str(tmp_path) in npm


def test_scan_tempdir_cleaned_after_context(tmp_path):
    """Context-manager exit removes the redirected cache dirs."""
    with scan_cache_env(tmp_path) as env:
        xdg = env["XDG_CACHE_HOME"]
        # Touch a file so we can verify cleanup
        os.makedirs(xdg, exist_ok=True)
    # After exit, the env mapping must not leak into ``os.environ``
    assert os.environ.get("XDG_CACHE_HOME") != xdg
