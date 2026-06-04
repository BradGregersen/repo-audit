"""Plan 08-03 Task 2 — squawk collector (RLS-02 migration-safety, native JSON).

squawk is the RLS-02 migration-safety FLOOR. Unlike pgrls it has NO SARIF
reporter (RESEARCH Pitfall 3 / A5 — squawk emits json/tty/gcc/gitlab only), so
it is mapped by a BESPOKE native-JSON adapter, NOT through ``sarif_to_findings``.
It is pure static SQL-text linting (NO DB) over the discovered SQL files, so it
is independent of the ephemeral-PG infra.

These tests drive the mapper OFFLINE against the frozen ``squawk_json_fixture``
(real squawk-cli 2.55.0 output over a destructive migration) and drive
``collect_squawk`` with ``resolve_tool`` / ``run_tool`` monkeypatched — no
binary, no DB, no network. Every mapped Finding must be ``static`` / ``candidate``
and pass the CRIT-4 verify-phrasing tripwire.
"""
from __future__ import annotations

import json

import pytest

import repo_audit.adapters.supabase.squawk_collect as squawk_mod
from repo_audit.adapters.supabase.squawk_collect import (
    _SQUAWK_LEVEL_TO_SEVERITY,
    _SQUAWK_RULE_TO_DIMENSION,
    collect_squawk,
    map_squawk_json,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)


class _FakeInvocation:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.command: list[str] = []
        self.duration_ms = 0.0


def _patch_resolve(monkeypatch, *, found: bool):
    def _fake_resolve(tool, scan_target, **_kw):
        if tool == "squawk" and found:
            return scan_target / "squawk"
        return None

    monkeypatch.setattr(squawk_mod, "resolve_tool", _fake_resolve)


def _patch_run(monkeypatch, invocation: _FakeInvocation):
    def _fake_run(argv, *, env, cwd, timeout_seconds):
        return invocation

    monkeypatch.setattr(squawk_mod, "run_tool", _fake_run)


# --- map_squawk_json: shape + invariants ----------------------------------


def test_one_finding_per_violation(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    assert len(findings) == len(squawk_json_fixture)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    assert all(f.source_tool == "squawk" for f in findings)


def test_rule_id_is_squawk_rule_name(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    rule_ids = {f.rule_id for f in findings}
    assert "ban-drop-column" in rule_ids
    assert "require-concurrent-index-creation" in rule_ids


def test_no_sarif_path_no_critical(squawk_json_fixture):
    # squawk levels map deterministically and are capped at major for candidate
    # (SCH-04) — never critical/blocker.
    findings = map_squawk_json(squawk_json_fixture)
    assert all(f.severity not in {"critical", "blocker"} for f in findings)


def test_level_to_severity_is_deterministic_and_pinned():
    # The pinned table: squawk Warning -> minor, Error -> major (capped).
    assert _SQUAWK_LEVEL_TO_SEVERITY["Warning"] == "minor"
    assert _SQUAWK_LEVEL_TO_SEVERITY["Error"] == "major"


def test_dimension_routing_destructive_to_correctness(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    by_rule = {f.rule_id: f for f in findings}
    # A destructive/lock-taking migration is a correctness/safety smell.
    assert by_rule["ban-drop-column"].dimension == "correctness"
    assert (
        by_rule["require-concurrent-index-creation"].dimension == "correctness"
    )


def test_dimension_routing_table_documented():
    # The routing table exists and routes the destructive rules to correctness.
    assert _SQUAWK_RULE_TO_DIMENSION["ban-drop-column"] == "correctness"


def test_file_line_carried_onto_finding(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    drop = next(f for f in findings if f.rule_id == "ban-drop-column")
    assert drop.file == "supabase/migrations/0009_destructive.sql"
    assert drop.line == 1
    # line_range echoes the squawk line.
    assert drop.evidence.line_range == (1, 1)


def test_raw_entry_in_parsed_value(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    drop = next(f for f in findings if f.rule_id == "ban-drop-column")
    raw = drop.evidence.parsed_value
    # The raw squawk entry is preserved (file/line/rule_name at minimum).
    assert raw.get("rule_name") == "ban-drop-column"
    assert raw.get("file") == "supabase/migrations/0009_destructive.sql"


def test_findings_pass_verify_phrasing(squawk_json_fixture):
    findings = map_squawk_json(squawk_json_fixture)
    assert_verify_phrasing(findings)  # no raise


def test_empty_payload_yields_no_findings():
    assert map_squawk_json([]) == []


# --- collect_squawk: invocation + degrade ---------------------------------


def test_collect_ok_findings(tmp_path, monkeypatch, squawk_json_fixture):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout=json.dumps(squawk_json_fixture), returncode=0),
    )
    sql_files = [tmp_path / "supabase" / "migrations" / "0009_destructive.sql"]

    result = collect_squawk(
        sql_files, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "ok"
    assert len(result.findings) == len(squawk_json_fixture)
    assert result.source_tool == "squawk"


def test_collect_absent_binary_is_unavailable_never_raises(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=False)

    def _exploding_run(*a, **k):  # pragma: no cover
        raise AssertionError("run_tool must not be called when squawk is absent")

    monkeypatch.setattr(squawk_mod, "run_tool", _exploding_run)

    result = collect_squawk(
        [tmp_path / "x.sql"], env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"
    assert result.findings == []
    assert result.source_tool == "squawk"


def test_collect_malformed_json_is_unavailable_never_raises(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout="not json at all", returncode=1),
    )

    result = collect_squawk(
        [tmp_path / "x.sql"], env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"
    assert result.findings == []


def test_collect_timeout(tmp_path, monkeypatch):
    from repo_audit.adapters.toolops import TIMED_OUT

    _patch_resolve(monkeypatch, found=True)
    _patch_run(monkeypatch, _FakeInvocation(returncode=TIMED_OUT))

    result = collect_squawk(
        [tmp_path / "x.sql"], env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "timeout"


def test_collect_no_sql_files_is_unavailable(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=True)

    def _exploding_run(*a, **k):  # pragma: no cover
        raise AssertionError("run_tool must not be called with no SQL files")

    monkeypatch.setattr(squawk_mod, "run_tool", _exploding_run)

    result = collect_squawk(
        [], env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"
