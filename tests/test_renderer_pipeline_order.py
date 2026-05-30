"""D-64 LOCKED chokepoint order — runtime ordering test.

Pins the contractual sequence:
  secret_lint → completion_honesty_lint → check_faithfulness
  → dilution_strip_exec_summary → corroboration_classify → _write_outputs

The static line-order grep test in 04-08 acceptance_criteria is a
structural sibling; this test pins it AT RUNTIME by spying on the
chokepoint function calls.
"""
from __future__ import annotations

from datetime import date

import pytest

pytest.importorskip("claude_agent_sdk", reason="Phase 4 SDK plumbing required")


def test_chokepoint_order(tmp_path, monkeypatch):
    """Assert the D-64 locked chokepoint sequence at runtime."""
    from repo_audit.agent.schema import AgentScanReport, DimensionNarrative
    from repo_audit.render import renderer as renderer_mod
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    call_order: list[str] = []

    # Spy wrappers — record the call and delegate to the real fn (so the
    # render still produces a buffer for downstream steps).
    #
    # SECRET-LINT-SPLIT-01 (Plan 05.1-02): the renderer's secret-lint site is
    # now ``lint_and_redact_entropy`` (gitleaks/known-patterns hard-block;
    # entropy-backstop redact-and-continue) rather than ``lint_buffer``. The
    # FIRST stage of the locked D-64 chokepoint order is unchanged (secret-lint
    # still runs first); we keep the internal "lint_buffer" call-order label so
    # the asserted lock-order below stays a stable contract string.
    real_lint_buffer = renderer_mod.lint_and_redact_entropy
    real_completion = renderer_mod.completion_honesty_lint
    real_faithfulness = renderer_mod.check_faithfulness
    real_dilution = renderer_mod.dilution_strip_exec_summary
    real_classify = renderer_mod.classify_critical_finding

    def spy_lint_buffer(*a, **k):
        # Only record the FIRST call (the agent-narrative pass per D-64);
        # the second-pass full-buffer call is a defense-in-depth repeat.
        buf_name = k.get("buffer_name", "")
        if buf_name == "agent-narrative":
            call_order.append("lint_buffer")
        elif not any(name == "lint_buffer" for name in call_order):
            call_order.append("lint_buffer")
        return real_lint_buffer(*a, **k)

    def spy_completion(*a, **k):
        buf_name = k.get("buffer_name", "")
        if buf_name == "agent-narrative":
            call_order.append("completion_honesty_lint")
        elif not any(name == "completion_honesty_lint" for name in call_order):
            call_order.append("completion_honesty_lint")
        return real_completion(*a, **k)

    def spy_faithfulness(*a, **k):
        call_order.append("check_faithfulness")
        return real_faithfulness(*a, **k)

    def spy_dilution(*a, **k):
        call_order.append("dilution_strip_exec_summary")
        return real_dilution(*a, **k)

    def spy_classify(*a, **k):
        if "classify_critical_finding" not in call_order:
            call_order.append("classify_critical_finding")
        return real_classify(*a, **k)

    monkeypatch.setattr(renderer_mod, "lint_and_redact_entropy", spy_lint_buffer)
    monkeypatch.setattr(renderer_mod, "completion_honesty_lint", spy_completion)
    monkeypatch.setattr(renderer_mod, "check_faithfulness", spy_faithfulness)
    monkeypatch.setattr(renderer_mod, "dilution_strip_exec_summary", spy_dilution)
    monkeypatch.setattr(renderer_mod, "classify_critical_finding", spy_classify)

    meta = ReportMeta(
        repo_slug="x",
        commit_sha="abc",
        scan_date=date.today(),
        tool_version="0.1.0",
        agent_status="ok",
    )
    scan_report = ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())
    agent_output = AgentScanReport(
        dimensions=[
            DimensionNarrative(
                dimension="quality",
                narrative="Baseline narrative.",
                severity_calls=[],
            )
        ],
        executive_summary="Clean run.",
        cross_cutting_notes=None,
    )

    md_path = tmp_path / "r.md"
    json_path = tmp_path / "r.json"
    rc = renderer_mod.render_and_write(
        scan_report, md_path, json_path, agent_output=agent_output,
    )
    assert rc == 0

    # D-64 LOCKED ORDER — the contractual first-occurrence sequence is:
    # lint_buffer -> completion_honesty_lint -> check_faithfulness -> dilution_strip_exec_summary -> classify_critical_finding
    # (classify_critical_finding follows only when blocker/critical findings exist).
    expected = [
        "lint_buffer",
        "completion_honesty_lint",
        "check_faithfulness",
        "dilution_strip_exec_summary",
    ]
    # classify_critical_finding is optional if there are no blocker/critical
    # findings — when there are findings, it appears AFTER dilution_strip.
    observed_first_occurrences = []
    seen: set[str] = set()
    for name in call_order:
        if name not in seen:
            observed_first_occurrences.append(name)
            seen.add(name)
    assert observed_first_occurrences[: len(expected)] == expected, (
        f"D-64 LOCKED ORDER violated. "
        f"Expected first occurrences to start with {expected}, "
        f"got {observed_first_occurrences}"
    )
