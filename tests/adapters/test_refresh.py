"""Phase 3 plan 03-06 — refresh.py contract tests.

The importorskip line below is kept per Wave 0b's pattern. Once the symbol
lands, the importorskip is a no-op and the test bodies execute. Plan 03-06
rewrites the test bodies (the Wave 0b scaffolding used an old shape:
``refresh_coverage(repo, timeout_s=10)`` returning ``RefreshResult.ok``).

The canonical contract is now:

    refresh_coverage(repo_root: Path, cfg: dict, env: dict[str, str]) -> RefreshResult

with ``RefreshResult.status: Literal["ok", "failed", "timeout", "skipped"]``,
``exit_code: int | None``, bounded ``stdout_tail`` and ``stderr_tail`` (≤2 KB
each via ``_TAIL_CAP``), and ``runner_command`` / ``duration_ms`` / ``notes`` /
``lcov_produced`` fields. Plan 03-03's ``_refresh_failed_finding`` helper
consumes ``stderr_tail`` / ``runner_command`` / ``duration_ms`` / ``exit_code``
directly when constructing the ``evidence_type='failed'`` Finding.

Test coverage spans:

    * Pydantic shape: ``extra='forbid'`` + default ``exit_code=None``.
    * Success / failed (nonzero exit) / failed (no lcov produced) / timeout /
      FileNotFoundError paths.
    * Structural hygiene: argv is list[str], ``shell=False``, cwd is repo_root
      (T-03-refresh-injection).
    * Env scrub: secret-shaped vars stripped (T-03-refresh-env-leak).
    * Stdout AND stderr tails bounded to 2048 bytes (M2 / T-03-refresh-dos).
    * ``_TAIL_CAP`` constant pinned at 2048 (Decision C ≤2 KB acceptance).
    * Default command is ``["npm", "test"]`` when ``cfg["command"]`` is absent.
    * ``CONFIG['tools']['coverage_refresh']['mode']`` defaults to ``"off"``
      (Decision A backward-safe).
    * Separation of concerns: refresh.py does NOT import ``Finding`` — the
      Finding-shape boundary lives in plan 03-03's ``_refresh_failed_finding``.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript.refresh",
    reason="optional module repo_audit.adapters.typescript.refresh not importable — feature not present in this build, or the install is incomplete",
)

from pydantic import ValidationError  # noqa: E402

from repo_audit.adapters.typescript.refresh import (  # noqa: E402
    RefreshResult,
    _TAIL_CAP,
    _scrub_secrets,
    refresh_coverage,
)


# --- RefreshResult Pydantic shape -----------------------------------------


def test_refresh_result_extra_forbid():
    """Unknown fields raise ValidationError (RefreshResult discipline)."""
    with pytest.raises(ValidationError):
        RefreshResult(status="ok", unknown_field="x")  # type: ignore[call-arg]


def test_refresh_result_default_exit_code_is_none():
    """exit_code defaults to None when not explicitly set."""
    r = RefreshResult(status="ok")
    assert r.exit_code is None


# --- refresh_coverage happy + failure paths --------------------------------


def test_refresh_coverage_success_path(tmp_path, fp):
    """Returncode 0 + lcov.info produced ⇒ status='ok', exit_code=0."""
    # Pre-create coverage/lcov.info to simulate the runner producing it.
    cov_dir = tmp_path / "coverage"
    cov_dir.mkdir()
    (cov_dir / "lcov.info").write_text("TN:\nSF:src/x.ts\nend_of_record\n", encoding="utf-8")
    fp.register(["npm", "test"], stdout="ok output", stderr="", returncode=0)

    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )

    assert result.status == "ok"
    assert result.lcov_produced is True
    assert result.runner_command == ["npm", "test"]
    assert result.exit_code == 0
    assert "coverage refreshed" in result.notes


def test_refresh_coverage_failed_nonzero_exit(tmp_path, fp):
    """Non-zero returncode ⇒ status='failed', exit_code=actual, notes mention exit code."""
    fp.register(["npm", "test"], stdout="", stderr="something broke", returncode=1)

    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )

    assert result.status == "failed"
    assert result.exit_code == 1
    assert "runner exit 1" in result.notes


def test_refresh_coverage_failed_no_lcov(tmp_path, fp):
    """Returncode 0 but no lcov.info produced ⇒ status='failed', exit_code=0."""
    fp.register(["npm", "test"], stdout="", stderr="", returncode=0)

    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )

    assert result.status == "failed"
    assert result.lcov_produced is False
    assert result.exit_code == 0
    assert "coverage/lcov.info not produced" in result.notes


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_refresh_coverage_timeout(tmp_path, monkeypatch):
    """TimeoutExpired ⇒ status='timeout', exit_code=None, notes mentions timeout."""

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0] if args else "?", timeout=0.1)

    monkeypatch.setattr("subprocess.run", boom)
    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 100},
        {"PATH": "/usr/bin"},
    )

    assert result.status == "timeout"
    assert result.exit_code is None
    assert "timeout after" in result.notes


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_refresh_coverage_filenotfound(tmp_path, monkeypatch):
    """FileNotFoundError (binary absent) ⇒ status='failed', exit_code=None."""

    def boom(*args, **kwargs):
        raise FileNotFoundError("no npm")

    monkeypatch.setattr("subprocess.run", boom)
    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )

    assert result.status == "failed"
    assert result.exit_code is None
    assert "FileNotFoundError" in result.notes


# --- Structural hygiene (T-03-refresh-injection) --------------------------


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_refresh_coverage_argv_is_list_str(tmp_path, monkeypatch):
    """The subprocess argv MUST be the literal list passed; shell=False; cwd=str(repo_root)."""
    captured: dict = {}

    def capture(*args, **kwargs):
        # DI-11-01-01: refresh_coverage runs the runner FIRST, then on the
        # success path calls _redact_tail(stdout/stderr) which invokes gitleaks
        # via subprocess.run (the secret-lint primitive). subprocess.run is
        # monkeypatched globally, so we must record only the FIRST call (the
        # runner) — a later record would capture the gitleaks argv instead.
        if "args" not in captured:
            captured["args"] = args
            captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args=args[0] if args else [], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr("subprocess.run", capture)
    refresh_coverage(
        tmp_path,
        {"command": ["npm", "test", "--", "--ci"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )

    assert captured["args"][0] == ["npm", "test", "--", "--ci"]
    assert captured["kwargs"].get("shell") is False
    assert captured["kwargs"].get("cwd") == str(tmp_path)


# --- Env scrub (T-03-refresh-env-leak) ------------------------------------


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_refresh_coverage_env_scrub_strips_secrets(tmp_path, monkeypatch):
    """Secret-shaped env vars (token/key/secret/password) stripped before subprocess."""
    captured_env: dict = {}

    def capture(*args, **kwargs):
        captured_env.update(kwargs.get("env") or {})
        return subprocess.CompletedProcess(
            args=args[0] if args else [], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr("subprocess.run", capture)
    refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {
            "GITHUB_TOKEN": "x",
            "AWS_ACCESS_KEY": "y",
            "API_SECRET": "z",
            "DB_PASSWORD": "w",
            "REDIS_PASSWD": "v",
            "PATH": "/usr/bin",
            "CI": "1",
        },
    )

    # Stripped:
    assert "GITHUB_TOKEN" not in captured_env
    assert "AWS_ACCESS_KEY" not in captured_env
    assert "API_SECRET" not in captured_env
    assert "DB_PASSWORD" not in captured_env
    assert "REDIS_PASSWD" not in captured_env
    # Preserved:
    assert captured_env.get("PATH") == "/usr/bin"
    assert captured_env.get("CI") == "1"


def test_scrub_secrets_unit():
    """_scrub_secrets removes any *_TOKEN / *_KEY / *_SECRET / *_PASSWORD / *_PASSWD."""
    result = _scrub_secrets(
        {"GITHUB_TOKEN": "x", "FOO": "y", "BAR_PASSWORD": "z", "PATH": "/p"}
    )
    assert result == {"FOO": "y", "PATH": "/p"}


# --- Output-tail bounding (M2 / T-03-refresh-dos) --------------------------


def test_stderr_tail_capped_at_2048(tmp_path, monkeypatch):
    """stderr longer than 2 KB is truncated before reaching RefreshResult."""
    huge_stderr = "x" * 5000

    def capture(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0] if args else [],
            returncode=1,
            stdout="",
            stderr=huge_stderr,
        )

    monkeypatch.setattr("subprocess.run", capture)
    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )
    assert len(result.stderr_tail) <= 2048


def test_stdout_tail_capped_at_2048(tmp_path, monkeypatch):
    """stdout longer than 2 KB is truncated before reaching RefreshResult."""
    huge_stdout = "y" * 5000

    def capture(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0] if args else [],
            returncode=0,
            stdout=huge_stdout,
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", capture)
    result = refresh_coverage(
        tmp_path,
        {"command": ["npm", "test"], "timeout_ms": 60_000},
        {"PATH": "/usr/bin"},
    )
    assert len(result.stdout_tail) <= 2048


def test_tail_cap_constant_is_2048():
    """Pin _TAIL_CAP at 2048 bytes (Decision C ≤2 KB acceptance — no downgrade to 512)."""
    assert _TAIL_CAP == 2048


# --- Default config behavior ----------------------------------------------


# real_subprocess: installs its own subprocess.run fake.
@pytest.mark.real_subprocess
def test_default_command_is_npm_test(tmp_path, monkeypatch):
    """When cfg has no 'command', refresh_coverage defaults to ['npm', 'test']."""
    captured: dict = {}

    def capture(*args, **kwargs):
        # DI-11-01-01: record only the FIRST subprocess.run (the runner). The
        # success path then calls _redact_tail → gitleaks via subprocess.run,
        # which would otherwise overwrite the captured argv.
        if "argv" not in captured:
            captured["argv"] = args[0]
        return subprocess.CompletedProcess(
            args=args[0] if args else [], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr("subprocess.run", capture)
    refresh_coverage(
        tmp_path,
        {},  # empty cfg → defaults
        {"PATH": "/usr/bin"},
    )
    assert captured["argv"] == ["npm", "test"]


def test_config_coverage_refresh_default_mode_is_off():
    """adapter.yaml ships coverage_refresh.mode='off' (Decision A backward-safe)."""
    from repo_audit.adapters.typescript import CONFIG

    assert CONFIG["tools"]["coverage_refresh"]["mode"] == "off"


# --- Separation of concerns -----------------------------------------------


def test_refresh_does_not_import_finding():
    """refresh.py never imports Finding — the Finding boundary lives in plan 03-03's helper."""
    import repo_audit.adapters.typescript.refresh as rmod

    src = Path(rmod.__file__).read_text(encoding="utf-8")
    # Two structural pins: no schema import, no Finding import.
    assert "from repo_audit.schema" not in src, (
        "refresh.py must not import from repo_audit.schema — Finding boundary is plan 03-03's helper"
    )
    assert "import Finding" not in src, (
        "refresh.py must not import Finding — Finding boundary is plan 03-03's helper"
    )
