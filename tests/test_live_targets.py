"""Unit tests for the live-target helpers and the skip reasons they print."""
from __future__ import annotations

import pytest

from tests.live_targets import (
    LIVE_COMPANION_ENV,
    LIVE_TARGET_ENV,
    live_companion_root,
    live_target_root,
    require_live_companion,
    require_live_target,
)


def test_env_var_names():
    assert LIVE_TARGET_ENV == "REPO_AUDIT_LIVE_TARGET"
    assert LIVE_COMPANION_ENV == "REPO_AUDIT_LIVE_COMPANION"


@pytest.mark.parametrize(
    ("env", "root_fn"),
    [(LIVE_TARGET_ENV, live_target_root), (LIVE_COMPANION_ENV, live_companion_root)],
)
def test_root_unset_empty_and_set(monkeypatch, tmp_path, env, root_fn):
    monkeypatch.delenv(env, raising=False)
    assert root_fn() is None
    monkeypatch.setenv(env, "")
    assert root_fn() is None
    monkeypatch.setenv(env, str(tmp_path))
    assert root_fn() == tmp_path


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [((), {}), (("node_modules",), {}), (("packages/api-client/sql",), {}), ((), {"git": True})],
)
def test_require_live_target_unset_names_the_variable(monkeypatch, args, kwargs):
    monkeypatch.delenv(LIVE_TARGET_ENV, raising=False)
    with pytest.raises(pytest.skip.Exception) as e:
        require_live_target(*args, **kwargs)
    msg = str(e.value)
    assert "REPO_AUDIT_LIVE_TARGET" in msg
    assert "/path/to" not in msg


def test_require_live_companion_unset_names_the_variable(monkeypatch):
    monkeypatch.delenv(LIVE_COMPANION_ENV, raising=False)
    with pytest.raises(pytest.skip.Exception) as e:
        require_live_companion()
    msg = str(e.value)
    assert "REPO_AUDIT_LIVE_COMPANION" in msg
    assert "/path/to" not in msg


@pytest.mark.parametrize(
    ("env", "call"),
    [
        (LIVE_TARGET_ENV, lambda: require_live_target()),
        (LIVE_COMPANION_ENV, lambda: require_live_companion()),
    ],
)
def test_require_missing_root(monkeypatch, tmp_path, env, call):
    monkeypatch.setenv(env, str(tmp_path / "missing"))
    with pytest.raises(pytest.skip.Exception) as e:
        call()
    msg = str(e.value)
    assert env in msg
    assert "does not exist" in msg


def test_require_live_target_missing_subpath(monkeypatch, tmp_path):
    monkeypatch.setenv(LIVE_TARGET_ENV, str(tmp_path))
    with pytest.raises(pytest.skip.Exception) as e:
        require_live_target("node_modules")
    msg = str(e.value)
    assert LIVE_TARGET_ENV in msg
    assert "node_modules" in msg
    assert "does not exist" in msg


def test_require_live_target_not_a_git_repo(monkeypatch, tmp_path):
    monkeypatch.setenv(LIVE_TARGET_ENV, str(tmp_path))
    with pytest.raises(pytest.skip.Exception) as e:
        require_live_target(git=True)
    assert "not a git repo" in str(e.value)


def test_require_live_companion_not_a_git_repo(monkeypatch, tmp_path):
    monkeypatch.setenv(LIVE_COMPANION_ENV, str(tmp_path))
    with pytest.raises(pytest.skip.Exception) as e:
        require_live_companion()
    assert "not a git repo" in str(e.value)


def test_require_live_target_returns_subpath(monkeypatch, tmp_path):
    (tmp_path / "node_modules").mkdir()
    monkeypatch.setenv(LIVE_TARGET_ENV, str(tmp_path))
    assert require_live_target("node_modules") == tmp_path / "node_modules"


def test_require_live_target_git_returns_root(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    monkeypatch.setenv(LIVE_TARGET_ENV, str(tmp_path))
    assert require_live_target(git=True) == tmp_path


def test_require_live_companion_returns_root(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    monkeypatch.setenv(LIVE_COMPANION_ENV, str(tmp_path))
    assert require_live_companion() == tmp_path
