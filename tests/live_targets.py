"""Where the live end-to-end tests find real repositories to scan.

Most of the suite runs against synthetic repos built under ``tmp_path``. A few
tests need real checkouts instead, and they read two environment variables:

- ``REPO_AUDIT_LIVE_TARGET``: the root of a checkout of a multi-stack app. Tests
  that exercise the TypeScript toolchain use its installed ``node_modules/``;
  the Supabase tests use the numbered SQL migrations under
  ``packages/api-client/sql``.
- ``REPO_AUDIT_LIVE_COMPANION``: a second git repository, scanned by the
  entropy-redaction canary.

When a variable is unset, or points somewhere that lacks what a test needs, the
test skips with a reason that names the variable.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

__all__ = [
    "LIVE_TARGET_ENV",
    "LIVE_COMPANION_ENV",
    "live_target_root",
    "live_companion_root",
    "require_live_target",
    "require_live_companion",
]

LIVE_TARGET_ENV: str = "REPO_AUDIT_LIVE_TARGET"
LIVE_COMPANION_ENV: str = "REPO_AUDIT_LIVE_COMPANION"


def _root_from_env(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return Path(value).expanduser()


def live_target_root() -> Path | None:
    """Return the path in ``REPO_AUDIT_LIVE_TARGET``, or None when unset or empty."""
    return _root_from_env(LIVE_TARGET_ENV)


def live_companion_root() -> Path | None:
    """Return the path in ``REPO_AUDIT_LIVE_COMPANION``, or None when unset or empty."""
    return _root_from_env(LIVE_COMPANION_ENV)


def require_live_target(subpath: str | None = None, *, git: bool = False) -> Path:
    """Return the live target (or a directory under it), skipping the test if unavailable."""
    root = live_target_root()
    if root is None:
        pytest.skip(f"set {LIVE_TARGET_ENV} to a checkout of a multi-stack app to run this test")
    if not root.exists():
        pytest.skip(f"{LIVE_TARGET_ENV} is set but {root} does not exist")
    if git and not (root / ".git").exists():
        pytest.skip(f"{LIVE_TARGET_ENV} is set but {root} is not a git repo")
    if subpath:
        path = root / subpath
        if not path.is_dir():
            pytest.skip(f"{LIVE_TARGET_ENV} is set but {path} does not exist")
        return path
    return root


def require_live_companion() -> Path:
    """Return the companion repo, skipping the test if unavailable."""
    root = live_companion_root()
    if root is None:
        pytest.skip(f"set {LIVE_COMPANION_ENV} to a second git repo to run the redaction canary")
    if not root.exists():
        pytest.skip(f"{LIVE_COMPANION_ENV} is set but {root} does not exist")
    if not (root / ".git").exists():
        pytest.skip(f"{LIVE_COMPANION_ENV} is set but {root} is not a git repo")
    return root
