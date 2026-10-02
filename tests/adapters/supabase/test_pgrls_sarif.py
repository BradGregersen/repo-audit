"""Plan 08-03 Task 1 — pgrls collector (flag-gated SARIF, try/unavailable degrade).

pgrls is the ADDITIVE RLS-01 layer (D-08-06): a 5-week-old v0.x Beta tool that
earns its place behind an explicit ``--rls-pgrls`` flag (the gating itself lands
in Plan 05) and a graceful-degrade wrapper (D-08-07). Its SARIF routes through
the ONE shared ``sarif_to_findings`` path (D-08-14 — pgrls is the only SARIF
source this phase) with a pgrls-specific ``severity_map``. ANY failure mode
(absent binary, timeout, malformed JSON, parser surprise) degrades to
``AdapterResult(status="unavailable")`` — never a raise, never a crashed
dimension; the splinter floor (Plan 02) still produces the RLS findings.

These tests drive ``collect_pgrls`` OFFLINE: ``resolve_tool`` /  ``run_tool`` are
monkeypatched so no pgrls binary, no live DB, and no network is touched. The
SARIF body is the frozen ``pgrls_sarif_fixture`` (Plan 01).
"""
from __future__ import annotations

import json

import pytest

import repo_audit.adapters.supabase.pgrls_collect as pgrls_mod
from repo_audit.adapters.supabase.pgrls_collect import (
    PGRLS_SEVERITY,
    collect_pgrls,
    pgrls_version,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)

_DSN = "postgresql://supabase_admin:pw@127.0.0.1:5432/postgres"


class _FakeInvocation:
    """Minimal stand-in for toolops.InvocationResult (the run_tool envelope)."""

    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.command: list[str] = []
        self.duration_ms = 0.0


def _patch_resolve(monkeypatch, *, found: bool):
    """Make resolve_tool('pgrls', ...) return a fake path or None."""

    def _fake_resolve(tool, scan_target, **_kw):
        if tool == "pgrls" and found:
            return scan_target / "pgrls"
        return None

    monkeypatch.setattr(pgrls_mod, "resolve_tool", _fake_resolve)


def _patch_run(monkeypatch, invocation: _FakeInvocation):
    """Make run_tool(...) return a canned invocation (no real subprocess)."""

    def _fake_run(argv, *, env, cwd, timeout_seconds):
        return invocation

    monkeypatch.setattr(pgrls_mod, "run_tool", _fake_run)


# --- Happy path: valid SARIF -> ok findings -------------------------------


def test_valid_sarif_returns_ok_findings(tmp_path, monkeypatch, pgrls_sarif_fixture):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout=json.dumps(pgrls_sarif_fixture), returncode=0),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "ok"
    assert len(result.findings) >= 1
    assert all(f.source_tool == "pgrls" for f in result.findings)
    assert all(f.evidence_type == "static" for f in result.findings)
    assert all(f.confidence == "candidate" for f in result.findings)
    assert result.dimension == "security"


def test_valid_sarif_caps_critical_at_major(tmp_path, monkeypatch, pgrls_sarif_fixture):
    # The fixture carries security-severity 9.3 (-> faithful critical), which the
    # SARIF parser caps to 'major' at confidence=candidate (SCH-04). No emitted
    # finding may be critical/blocker.
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout=json.dumps(pgrls_sarif_fixture), returncode=0),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "ok"
    assert all(f.severity not in {"critical", "blocker"} for f in result.findings)
    # At least one capped finding preserves its faithful critical breadcrumb.
    capped = [
        f
        for f in result.findings
        if f.evidence.parsed_value.get("faithful_severity") == "critical"
    ]
    assert capped, "expected the security-severity 9.3 result to cap critical->major"
    assert all(f.severity == "major" for f in capped)


def test_findings_pass_verify_phrasing(tmp_path, monkeypatch, pgrls_sarif_fixture):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout=json.dumps(pgrls_sarif_fixture), returncode=0),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    # The collector calls this internally before returning ok; re-asserting here
    # proves the returned batch is CRIT-4-clean (no raise).
    assert_verify_phrasing(result.findings)


# --- Degrade paths: absent / malformed / timeout -> unavailable, never raise


def test_absent_binary_is_unavailable_never_raises(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=False)
    # run_tool must NOT even be called when the binary is absent; if it is, the
    # fake raising stub would surface the contract break.

    def _exploding_run(*a, **k):  # pragma: no cover - asserts it is never hit
        raise AssertionError("run_tool must not be called when pgrls is absent")

    monkeypatch.setattr(pgrls_mod, "run_tool", _exploding_run)

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"
    assert result.findings == []
    assert result.source_tool == "pgrls"
    assert result.dimension == "security"


def test_malformed_json_is_unavailable_never_raises(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(
            stdout="Traceback (most recent call last): pgrls crashed",
            stderr="panic",
            returncode=2,
        ),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"
    assert result.findings == []
    assert result.notes  # carries a bounded reason


def test_timeout_is_timeout_status_never_raises(tmp_path, monkeypatch):
    from repo_audit.adapters.toolops import TIMED_OUT

    _patch_resolve(monkeypatch, found=True)
    _patch_run(monkeypatch, _FakeInvocation(returncode=TIMED_OUT))

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "timeout"
    assert result.findings == []


def test_exec_failed_is_unavailable(tmp_path, monkeypatch):
    from repo_audit.adapters.toolops import EXEC_FAILED

    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stderr="binary not found", returncode=EXEC_FAILED),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "unavailable"


def test_empty_sarif_runs_is_ok_with_zero_findings(tmp_path, monkeypatch):
    _patch_resolve(monkeypatch, found=True)
    _patch_run(
        monkeypatch,
        _FakeInvocation(stdout=json.dumps({"version": "2.1.0", "runs": []}), returncode=0),
    )

    result = collect_pgrls(
        _DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path
    )

    assert result.status == "ok"
    assert result.findings == []


def _sarif_result(rule_id: str, text: str) -> dict:
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": text},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "public.profiles"}}}
        ],
    }


def test_one_overclaiming_finding_does_not_discard_the_layer(tmp_path, monkeypatch):
    """pgrls's own text uses 'enforced' descriptively (SEC022: "With RLS enforced
    and no write-side policy ..."). That finding is withheld and named; the rest
    of the pgrls layer still reaches the report."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "pgrls", "rules": []}},
                "results": [
                    _sarif_result(
                        "SEC022", "With RLS enforced and no write-side policy, writes fail."
                    ),
                    _sarif_result(
                        "SEC014", "Function public.f is SECURITY DEFINER; review its reach."
                    ),
                ],
            }
        ],
    }
    _patch_resolve(monkeypatch, found=True)
    _patch_run(monkeypatch, _FakeInvocation(stdout=json.dumps(sarif), returncode=0))

    result = collect_pgrls(_DSN, env={}, timeout_seconds=30.0, scan_target=tmp_path)

    assert result.status == "ok"
    assert [f.rule_id for f in result.findings] == ["SEC014"]
    assert "withheld 1 finding(s)" in result.notes
    assert "SEC022" in result.notes


# --- Provenance + severity-map shape --------------------------------------


def test_pgrls_version_is_a_pinned_string():
    ver = pgrls_version()
    assert isinstance(ver, str)
    assert ver  # non-empty; the installed dist metadata or the pinned constant


def test_pgrls_severity_map_shape():
    # error->critical/warning->major/note->minor/none->info (faithful; the parser
    # caps critical->major at candidate downstream).
    assert PGRLS_SEVERITY["error"] == "critical"
    assert PGRLS_SEVERITY["warning"] == "major"
    assert PGRLS_SEVERITY["note"] == "minor"
    assert PGRLS_SEVERITY["none"] == "info"
