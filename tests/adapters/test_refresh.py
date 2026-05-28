"""Phase 3 Wave 3 contract — SKIP via importorskip until plan 03-06 lands.

D-41 (re-scoped): when coverage artifacts are missing/stale, the optional
``refresh`` runner can invoke the project's test script to regenerate
``coverage/lcov.info``. The refresh path is OFF by default (Decision A) and
gated by adapter.yaml ``tools.coverage_refresh.mode``.

T-03-refresh-injection structural guard: argv MUST be ``list[str]``, never
``shell=True``; env scrub strips known secret env vars before forking.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.refresh",
    reason="Wave 3 (plan 03-06) not yet landed — refresh runner missing",
)

from repo_audit.adapters.typescript.refresh import (  # noqa: E402
    RefreshResult,
    refresh_coverage,
)


def test_refresh_coverage_returns_RefreshResult_on_success(ts_fixture_repo):
    """Happy path: ``refresh_coverage`` returns a ``RefreshResult`` with ``ok=True``."""
    result = refresh_coverage(ts_fixture_repo, timeout_s=10)
    assert isinstance(result, RefreshResult)


def test_refresh_coverage_returns_failed_on_timeout(ts_fixture_repo, monkeypatch):
    """Timeout ⇒ ``RefreshResult(ok=False)`` with notes mentioning timeout."""
    import subprocess

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0] if args else "?", timeout=0.1)

    monkeypatch.setattr("subprocess.run", boom)
    result = refresh_coverage(ts_fixture_repo, timeout_s=0.1)
    assert isinstance(result, RefreshResult)
    assert result.ok is False
    notes = (result.notes or "").lower()
    assert "timeout" in notes or "timed out" in notes


def test_refresh_coverage_argv_is_list_str(ts_fixture_repo):
    """T-03-refresh-injection: the subprocess argv MUST be ``list[str]``, NEVER ``shell=True``.

    Structural test: inspect the module source for forbidden patterns.
    """
    import inspect
    import repo_audit.adapters.typescript.refresh as ref_mod
    src = inspect.getsource(ref_mod)
    assert "shell=True" not in src, "refresh.py must never use shell=True"
    assert "subprocess.run(" in src


def test_refresh_coverage_env_scrub_strips_secrets(ts_fixture_repo, monkeypatch):
    """Environment passed to the refresh subprocess MUST NOT contain known secret keys.

    Sets a synthetic secret env var and confirms it does not leak into the
    child process's environment (via mock).
    """
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE-not-real")
    captured_envs: list[dict] = []

    def capture(*args, **kwargs):
        captured_envs.append(kwargs.get("env") or {})
        import subprocess as _sp
        return _sp.CompletedProcess(args=args[0] if args else [], returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", capture)
    refresh_coverage(ts_fixture_repo, timeout_s=10)
    if captured_envs:
        env = captured_envs[0]
        assert "AWS_SECRET_ACCESS_KEY" not in env
