"""A failed tool run must never read as a clean result.

Each external tool gets an explicit success set of exit codes. Anything outside
that set, output that cannot be read, or a run that did not finish maps to
``unavailable``, ``partial`` or ``timeout`` -- never to ``ok`` with zero
findings. These tests drive each adapter at its own boundary with recorded or
synthesized tool output, so they need no real binaries.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from repo_audit.adapters.base import InvocationResult

_FIXTURES = Path(__file__).parent / "adapters" / "fixtures"


def _recorded(tool: str, scenario: str) -> tuple[str, str, int]:
    """Read ``(stdout, stderr, returncode)`` from a recorded tool fixture."""
    base = _FIXTURES / tool / scenario
    stdout = (base / "stdout.txt").read_text(encoding="utf-8")
    stderr = (base / "stderr.txt").read_text(encoding="utf-8")
    rc = int((base / "returncode.txt").read_text(encoding="utf-8").strip())
    return stdout, stderr, rc


# --- TypeScript project tools: eslint, tsc, knip ----------------------------


def _run_ts_tool(monkeypatch, tmp_path, tool, stdout, stderr, rc):
    from repo_audit.adapters import typescript as ts

    # The project's own install, as on a target where npm install has run.
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ts, "resolve_tool", lambda *a, **k: bin_dir / tool)
    monkeypatch.setattr(
        ts,
        "_invoke_subprocess",
        lambda *a, **k: InvocationResult(stdout=stdout, stderr=stderr, returncode=rc),
    )
    tool_cfg = ts.ADAPTER_CONFIG["tools"][tool]
    tempdir = tmp_path / "tmp"
    tempdir.mkdir(exist_ok=True)
    return ts._run_subprocess_tool(tool, tool_cfg, tmp_path, tempdir, {})


def _run_ts_recorded(monkeypatch, tmp_path, tool, scenario):
    stdout, stderr, rc = _recorded(tool, scenario)
    return _run_ts_tool(monkeypatch, tmp_path, tool, stdout, stderr, rc)


def test_eslint_config_failure_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "eslint", "fatal_config")
    assert result.status == "unavailable"
    assert "2" in result.notes
    assert "Could not load config" in result.notes


def test_eslint_malformed_json_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "eslint", "malformed_json")
    assert result.status == "unavailable"


@pytest.mark.parametrize("scenario", ["clean", "errors"])
def test_eslint_success_codes_are_ok(monkeypatch, tmp_path, scenario):
    result = _run_ts_recorded(monkeypatch, tmp_path, "eslint", scenario)
    assert result.status == "ok"
    if scenario == "errors":
        assert len(result.findings) >= 1


def test_tsc_exit_outside_success_set_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_tool(
        monkeypatch, tmp_path, "tsc", "", "tsc crashed", 3
    )
    assert result.status == "unavailable"
    assert "3" in result.notes


def test_tsc_nonzero_without_diagnostics_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "tsc", "internal_error")
    assert result.status == "unavailable"
    assert "TS5023" in result.notes


def test_tsc_diagnostics_are_ok(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "tsc", "errors")
    assert result.status == "ok"
    assert len(result.findings) >= 1


def test_tsc_clean_is_ok(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "tsc", "clean")
    assert result.status == "ok"


def test_knip_config_error_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_tool(monkeypatch, tmp_path, "knip", "", "config error", 2)
    assert result.status == "unavailable"
    assert "config error" in result.notes


def test_knip_malformed_json_is_unavailable(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "knip", "malformed")
    assert result.status == "unavailable"


def test_knip_clean_is_ok(monkeypatch, tmp_path):
    result = _run_ts_recorded(monkeypatch, tmp_path, "knip", "clean")
    assert result.status == "ok"


# --- semgrep ------------------------------------------------------------------


def _empty_sarif(notifications=None) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "version": "1.0.0"}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications or [],
                    }
                ],
            }
        ],
    }


def _run_semgrep(monkeypatch, tmp_path, stdout, rc, stderr=""):
    from repo_audit.adapters.sast import semgrep

    monkeypatch.setattr(semgrep, "resolve_tool", lambda *a, **k: Path("semgrep"))
    monkeypatch.setattr(
        semgrep,
        "run_tool",
        lambda *a, **k: InvocationResult(stdout=stdout, stderr=stderr, returncode=rc),
    )
    return semgrep.collect_semgrep(tmp_path, env={}, packs=["p/owasp-top-ten"])


def test_semgrep_exit_outside_success_set_is_unavailable(monkeypatch, tmp_path):
    result = _run_semgrep(
        monkeypatch, tmp_path, json.dumps(_empty_sarif()), 7, stderr="bad config"
    )
    assert result.status == "unavailable"
    assert "7" in result.notes


def test_semgrep_error_notification_is_unavailable(monkeypatch, tmp_path):
    sarif = _empty_sarif(
        [{"level": "error", "message": {"text": "pack p/does-not-exist not found"}}]
    )
    result = _run_semgrep(monkeypatch, tmp_path, json.dumps(sarif), 0)
    assert result.status == "unavailable"
    assert "pack p/does-not-exist not found" in result.notes


def test_semgrep_findings_exit_is_ok(monkeypatch, tmp_path):
    owasp = (_FIXTURES / "sast" / "owasp_top_ten.sarif").read_text(encoding="utf-8")
    result = _run_semgrep(monkeypatch, tmp_path, owasp, 1)
    assert result.status == "ok"
    assert len(result.findings) >= 1


# --- gitleaks -------------------------------------------------------------------


def _gitleaks_present(monkeypatch, secret_lint):
    real_which = secret_lint.shutil.which

    def _which(name, *args, **kwargs):
        if name == "gitleaks":
            return "/usr/local/bin/gitleaks"
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(secret_lint.shutil, "which", _which)


def _gitleaks_times_out(monkeypatch, secret_lint):
    def _raise(argv, *args, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))

    monkeypatch.setattr(
        secret_lint,
        "subprocess",
        SimpleNamespace(run=_raise, TimeoutExpired=subprocess.TimeoutExpired),
    )


@pytest.mark.parametrize("scan", ["scan_working_tree", "scan_git_history"])
def test_gitleaks_timeout_returns_none(monkeypatch, tmp_path, scan):
    from repo_audit.render import secret_lint

    _gitleaks_present(monkeypatch, secret_lint)
    _gitleaks_times_out(monkeypatch, secret_lint)
    assert getattr(secret_lint, scan)(tmp_path, timeout=5) is None


@pytest.mark.parametrize("scan", ["scan_working_tree", "scan_git_history"])
def test_gitleaks_absent_returns_empty(monkeypatch, tmp_path, scan):
    from repo_audit.render import secret_lint

    monkeypatch.setattr(secret_lint.shutil, "which", lambda *a, **k: None)
    assert getattr(secret_lint, scan)(tmp_path, timeout=5) == []


def test_secret_detection_gitleaks_timeout_is_partial(monkeypatch, fake_repo):
    from repo_audit.collectors import secret_detection
    from repo_audit.walker import build_repo_index

    monkeypatch.setattr(secret_detection, "GITLEAKS_AVAILABLE", True)
    monkeypatch.setattr(secret_detection, "scan_working_tree", lambda *a, **k: None)
    repo = fake_repo({"src/app.py": "print('hello')\n"}, name="plain")
    result = secret_detection.run(repo, build_repo_index(repo).index)
    assert result.status == "partial"
    assert "did not finish" in result.notes


def test_history_gitleaks_timeout_is_timeout(monkeypatch, secret_history_repo):
    from repo_audit.adapters.supply_chain import history

    monkeypatch.setattr(
        history.shutil, "which", lambda name, *a, **k: "/usr/local/bin/" + name
    )
    monkeypatch.setattr(history, "scan_git_history", lambda *a, **k: None)
    result = history.collect_git_history(secret_history_repo())
    assert result.status == "timeout"
