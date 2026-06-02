"""GATE tests for the runtime two-account wrapper (Plan 08-04, Task 2).

D-08-01: the runtime test NEVER auto-runs. It runs ONLY when ``opted_in`` is
True AND all six env-var NAMES resolve. Creds-present-without-the-flag still
does NOT run. In every not-run case: ZERO findings, NO enforcement language
anywhere, and ``run_tool`` is NEVER invoked (the honest ledger entry — D-08-05 —
is the disclosure).
"""
from __future__ import annotations

from pathlib import Path

import repo_audit.adapters.supabase.runtime_two_account as rt
from repo_audit.adapters.supabase.runtime_two_account import (
    _REQUIRED_ENV_NAMES,
    collect_runtime_two_account,
)

_ENFORCEMENT_WORDS = ("enforced", "secure", "protected", "leak", "passed")


def _full_env() -> dict[str, str]:
    return {name: f"value-for-{name}" for name in _REQUIRED_ENV_NAMES}


def _assert_no_enforcement_language(result) -> None:
    blob = result.notes.lower()
    for f in result.findings:
        blob += " ".join(
            [
                f.recommendation,
                f.confidence_caveat or "",
                f.evidence.output_snippet,
            ]
        ).lower()
    for word in _ENFORCEMENT_WORDS:
        assert word not in blob, f"unexpected enforcement word {word!r} in not-run path"


def test_required_env_names_are_exactly_the_six(tmp_path: Path) -> None:
    assert _REQUIRED_ENV_NAMES == [
        "EXPO_PUBLIC_SUPABASE_URL",
        "EXPO_PUBLIC_SUPABASE_ANON_KEY",
        "AUDIT_TEST_USER_A_EMAIL",
        "AUDIT_TEST_USER_A_PASSWORD",
        "AUDIT_TEST_USER_B_EMAIL",
        "AUDIT_TEST_USER_B_PASSWORD",
    ]
    assert len(_REQUIRED_ENV_NAMES) == 6


def test_opted_in_but_no_creds_does_not_run(tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(rt, "run_tool", lambda *a, **k: calls.append((a, k)))
    result = collect_runtime_two_account(
        tmp_path, opted_in=True, env={}, timeout_seconds=60.0
    )
    assert result.status == "unavailable"
    assert "not run" in result.notes.lower()
    assert "no creds" in result.notes.lower()
    assert result.findings == []
    assert calls == []  # run_tool NEVER called
    _assert_no_enforcement_language(result)


def test_creds_present_without_flag_never_runs(tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(rt, "run_tool", lambda *a, **k: calls.append((a, k)))
    result = collect_runtime_two_account(
        tmp_path, opted_in=False, env=_full_env(), timeout_seconds=60.0
    )
    assert result.status == "unavailable"
    assert "not opted in" in result.notes.lower()
    assert result.findings == []
    assert calls == []  # creds-present-without-flag => still NOT run (D-08-01)
    _assert_no_enforcement_language(result)


def test_partial_creds_does_not_run(tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(rt, "run_tool", lambda *a, **k: calls.append((a, k)))
    env = _full_env()
    del env["AUDIT_TEST_USER_B_PASSWORD"]  # one missing => gate closed
    result = collect_runtime_two_account(
        tmp_path, opted_in=True, env=env, timeout_seconds=60.0
    )
    assert result.status == "unavailable"
    assert result.findings == []
    assert calls == []
    _assert_no_enforcement_language(result)
