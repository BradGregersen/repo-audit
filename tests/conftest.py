"""Shared pytest fixtures for Phase 1 tests.

Fixture names defined here are referenced by every Phase 1 test file.
Changing a name here means updating every test that imports it.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pygit2
import pytest
from typer.testing import CliRunner


# --- Synthetic secret for REP-05 / SAFE-secret-lint tests ---
# AWS-key-shaped string with high enough Shannon entropy (>4.5 bits/char) to fire
# the entropy backstop AND match the gitleaks AWS access-key rule. NOT a real key.
_SYNTHETIC_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # 20 chars, AWS canonical example


@pytest.fixture
def synthetic_secret() -> str:
    """A known fake AWS access key for secret-lint tests.

    Used by tests/test_secret_lint.py to inject a synthetic high-entropy token
    into a render buffer and assert the secret-lint refuses the write.
    """
    return _SYNTHETIC_AWS_KEY


@pytest.fixture
def runner() -> CliRunner:
    """typer.testing.CliRunner instance (in-process invocation, no subprocess).

    Modern Typer/Click already separates stdout/stderr by default; the
    historical ``mix_stderr=False`` kwarg was removed (Rule 3 blocking
    auto-fix during Plan 01-05 -- previously masked by the module-level
    xfail on tests/test_secret_lint.py and the per-function xfails on
    tests/test_cli.py).
    """
    return CliRunner()


def _seed_repo(
    repo_path: Path,
    manifests: dict[str, str],
    *,
    commit_message: str = "init",
    commit_timestamp: int | None = None,
) -> Path:
    """Seed a git repo at repo_path with the given manifest files and one commit."""
    repo_path.mkdir(parents=True, exist_ok=True)
    repo = pygit2.init_repository(str(repo_path), bare=False)
    for rel_path, contents in manifests.items():
        f = repo_path / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(contents, encoding="utf-8")
    # Stage all
    repo.index.add_all()
    repo.index.write()
    tree = repo.index.write_tree()
    ts = commit_timestamp or int(_dt.datetime(2026, 5, 28, 12, 0, 0).timestamp())
    sig = pygit2.Signature("test-author", "test@example.com", ts, 0)
    repo.create_commit("HEAD", sig, sig, commit_message, tree, [])
    return repo_path


@pytest.fixture
def fake_repo(tmp_path):
    """Factory: build a pygit2-seeded fake repo with chosen manifests.

    Usage:
        def test_x(fake_repo):
            repo = fake_repo({"package.json": "{}", "tsconfig.json": "{}"})
            # repo is a Path with one commit; manifests written and committed
    """
    def _factory(manifests: dict[str, str] | None = None, *, name: str = "fake-repo") -> Path:
        repo_path = tmp_path / name
        return _seed_repo(repo_path, manifests or {})
    return _factory


@pytest.fixture
def polyglot_repo(tmp_path) -> Path:
    """A repo mirroring ~/Code/adapt's shape: TypeScript + Supabase.

    Used by tests/test_detect.py::test_detect_polyglot_repo and
    tests/test_cli.py::test_detect_command_lists_stacks.
    """
    return _seed_repo(
        tmp_path / "polyglot",
        {
            "package.json": '{"name": "polyglot", "dependencies": {"typescript": "^5.0.0"}}',
            "tsconfig.json": '{"compilerOptions": {"strict": true}}',
            "supabase/config.toml": '[api]\nport = 54321\n',
        },
    )


@pytest.fixture
def expo_supabase_repo(tmp_path) -> Path:
    """An Expo + Supabase repo: should detect BOTH stacks (Expo overrides plain TS)."""
    return _seed_repo(
        tmp_path / "expo-supabase",
        {
            "package.json": '{"name": "rn-app", "dependencies": {"expo": "~54.0.0"}}',
            "app.json": '{"expo": {"name": "rn-app"}}',
            "supabase/config.toml": "[api]\nport = 54321\n",
        },
    )


@pytest.fixture
def empty_repo(tmp_path) -> Path:
    """A repo with no recognized manifests (DETECT-03 — should return empty stack list)."""
    return _seed_repo(
        tmp_path / "empty-repo",
        {"README.md": "# empty\n"},
    )
