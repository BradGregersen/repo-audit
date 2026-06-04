"""EXIT-CODE -> evidence mapping tests for the runtime wrapper (Plan 08-04).

D-08-04: the actually-executed exit code is the SOLE source of runtime evidence.
  * exit 0 -> ONE evidence_type="runtime" finding asserting cross-tenant
    enforcement (the ONLY sanctioned enforcement language; assert_verify_phrasing
    EXEMPTS runtime), confidence confirmed (NOT candidate), severity info.
  * exit 1 -> ONE runtime LEAK finding at critical/blocker, dimension security,
    constructed WITHOUT a SCH-04 ValidationError (runtime != candidate).
  * exit 2 -> unavailable (setup/config).
  * -1 (node missing) / -2 (timeout) -> unavailable / timeout. Never raises.
Value-blind: the env reaching run_tool carries no secret-NAMED key into notes;
stdout/stderr route through _redact_tail before landing in notes.
"""
from __future__ import annotations

from pathlib import Path

import repo_audit.adapters.supabase.runtime_two_account as rt
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.supabase.runtime_two_account import (
    _REQUIRED_ENV_NAMES,
    collect_runtime_two_account,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT


def _full_env() -> dict[str, str]:
    return {name: f"value-for-{name}" for name in _REQUIRED_ENV_NAMES}


def _repo_with_script(tmp_path: Path) -> Path:
    script = tmp_path / "scripts" / "audit" / "rls-two-account-test.mjs"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("// stub\n", encoding="utf-8")
    return tmp_path


def _stub_run_tool(monkeypatch, returncode: int, stdout: str = "", stderr: str = ""):
    seen: dict = {}

    def _fake(argv, *, env, cwd, timeout_seconds):
        seen["argv"] = argv
        seen["env"] = env
        seen["cwd"] = cwd
        return InvocationResult(
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            command=list(argv),
        )

    monkeypatch.setattr(rt, "run_tool", _fake)
    # node resolves to a fake path so the gate passes the resolution step.
    monkeypatch.setattr(rt, "resolve_tool", lambda tool, target, **_kw: Path("/usr/bin/node"))
    return seen


def test_exit_0_is_one_runtime_enforced_finding(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    _stub_run_tool(monkeypatch, 0, stdout="SUMMARY: 20 probes")
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "ok"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.evidence_type == "runtime"
    assert f.confidence in ("corroborated", "confirmed")
    assert f.confidence != "candidate"
    assert f.dimension == "security"
    # Enforcement language permitted here (runtime is the sanctioned exemption).
    assert "enforced" in f.recommendation.lower()
    # The shared CRIT-4 tripwire must NOT raise on a runtime finding.
    assert_verify_phrasing(result.findings)


def test_exit_1_is_runtime_leak_at_blocker(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    _stub_run_tool(monkeypatch, 1, stdout="SUMMARY: 1 LEAK")
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "ok"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.evidence_type == "runtime"
    assert f.severity in ("critical", "blocker")
    assert f.confidence != "candidate"  # non-candidate => no SCH-04 ValidationError
    assert f.dimension == "security"
    assert "leak" in (f.rule_id + f.recommendation).lower()
    assert_verify_phrasing(result.findings)


def test_exit_2_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    _stub_run_tool(monkeypatch, 2, stderr="SETUP ERROR")
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "unavailable"
    assert result.findings == []
    assert "setup" in result.notes.lower() or "config" in result.notes.lower()


def test_exec_failed_sentinel_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    _stub_run_tool(monkeypatch, EXEC_FAILED, stderr="node not found")
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "unavailable"
    assert result.findings == []


def test_timeout_sentinel_is_timeout(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    _stub_run_tool(monkeypatch, TIMED_OUT)
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status in ("timeout", "unavailable")
    assert result.findings == []


def test_missing_script_in_repo_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    # No script written; resolve node fine, but the script path is absent.
    monkeypatch.setattr(rt, "resolve_tool", lambda tool, target, **_kw: Path("/usr/bin/node"))
    called: list = []
    monkeypatch.setattr(rt, "run_tool", lambda *a, **k: called.append(1))
    result = collect_runtime_two_account(
        tmp_path, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "unavailable"
    assert "script" in result.notes.lower()
    assert called == []  # never invoked node when the script is missing


def test_node_absent_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    monkeypatch.setattr(rt, "resolve_tool", lambda tool, target, **_kw: None)
    called: list = []
    monkeypatch.setattr(rt, "run_tool", lambda *a, **k: called.append(1))
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    assert result.status == "unavailable"
    assert called == []


def test_value_blind_output_routed_through_redaction(tmp_path: Path, monkeypatch) -> None:
    repo = _repo_with_script(tmp_path)
    # A fake AWS-shaped key in stdout must NOT survive verbatim into notes.
    leaky = "AKIAIOSFODNN7EXAMPLE secret printed by a misbehaving child"
    seen = _stub_run_tool(monkeypatch, 0, stdout=leaky)
    result = collect_runtime_two_account(
        repo, opted_in=True, env=_full_env(), timeout_seconds=120.0
    )
    # The six creds flow to the child env (the script needs them)...
    assert "EXPO_PUBLIC_SUPABASE_URL" in seen["env"]
    # ...but no secret-NAMED value lands in the report notes.
    for name in _REQUIRED_ENV_NAMES:
        assert f"value-for-{name}" not in result.notes
    assert "AKIAIOSFODNN7EXAMPLE" not in result.notes
