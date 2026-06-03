"""EXP-01 — expo-doctor collector contract test (Plan 11-01 Wave 0 scaffolding).

SKIPPED until the Wave-1 ``repo_audit.adapters.expo.doctor`` module lands,
then activates automatically.

expo-doctor is TEXT-ONLY — there is no JSON/SARIF flag (11-RESEARCH Pitfall 3).
The collector parses via exit code + stable line markers:
    * exit 0 -> all checks passed -> ONE info-level quality Finding.
    * non-zero -> at least one quality Finding (per-check OR aggregate-stdout-tail
      fallback — both acceptable, RESEARCH Pitfall 3 / Assumption A1), never raises.
    * absent tool -> one ``evidence_type='unavailable'`` Finding, never raises.

The pass/fail stdout fixtures are recorded under ``fixtures/`` (modelled on the
Pitfall-3 description; ASCII-safe).
"""
from __future__ import annotations

from pathlib import Path

import pytest

doctor = pytest.importorskip(
    "repo_audit.adapters.expo.doctor",
    reason="Wave 1 (plan 11-03) not yet landed — expo.doctor missing",
)

_FIXTURES = Path(__file__).parent / "fixtures"
_PASS = (_FIXTURES / "expo-doctor-pass.txt").read_text(encoding="utf-8")
_FAIL = (_FIXTURES / "expo-doctor-fail.txt").read_text(encoding="utf-8")


def test_exit_zero_emits_single_pass_finding(fp):
    """exit 0 -> exactly one quality Finding indicating all checks passed."""
    fp.register(["npx", "expo-doctor"], stdout=_PASS, returncode=0)

    findings = doctor.collect_expo_doctor(Path("/repo"), env={})

    assert len(findings) == 1
    f = findings[0]
    assert f.dimension == "quality"
    assert f.evidence_type == "static"
    blob = f"{f.recommendation} {f.evidence.output_snippet}".lower()
    assert "pass" in blob


def test_non_zero_emits_failure_findings_or_aggregate_fallback(fp):
    """Non-zero exit -> >=1 quality Finding, never raises (per-check OR fallback)."""
    fp.register(["npx", "expo-doctor"], stdout=_FAIL, returncode=1)

    findings = doctor.collect_expo_doctor(Path("/repo"), env={})

    assert len(findings) >= 1
    assert all(f.dimension == "quality" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)


def test_absent_tool_unavailable(monkeypatch):
    """Absent expo-doctor -> one evidence_type='unavailable' Finding, no raise."""
    # Force the tool-resolution seam to report the command unavailable.
    if hasattr(doctor, "resolve_tool"):
        monkeypatch.setattr(doctor, "resolve_tool", lambda *a, **k: None)

    from repo_audit.adapters.base import InvocationResult
    from repo_audit.adapters.toolops import EXEC_FAILED

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        return InvocationResult(
            stdout="",
            stderr="command not found: expo-doctor",
            returncode=EXEC_FAILED,
            command=list(argv),
        )

    monkeypatch.setattr(doctor, "run_tool", fake_run_tool)

    findings = doctor.collect_expo_doctor(Path("/repo"), env={})

    assert len(findings) >= 1
    assert any(f.evidence_type == "unavailable" for f in findings)
