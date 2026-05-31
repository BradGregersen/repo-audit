"""Quick 260530-s1v — per-dimension agent narrative render + fallback (RENDER-DIM-NARR-01).

These tests render `state_report.md.j2` DIRECTLY via `_make_env()`. The
template-direct path bypasses the D-64 faithfulness pipeline, so the macro fix is
isolated from the gate: we are testing Jinja loop-scoping, not the agent or the
faithfulness validator.

- test_dimension_narrative_renders_when_present
    FAILS against the buggy loop-local `{% set dim_narrative %}` macro (the
    assignment is discarded after the `{% for %}` loop, so the narrative never
    renders) and PASSES once the macro uses a `namespace`.
- test_dimension_narrative_fallback_when_no_match
    The `agent_status != 'ok'` elif branch still fires for dimension sections
    that have no matching narrative.

Construction patterns (minimal ScanReport + ReportMeta with empty findings and a
ScopeLedger) mirror tests/test_render_fallback.py.
"""
from __future__ import annotations

from datetime import date


def _scan_report(**meta_overrides):
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger

    base = dict(
        repo_slug="x",
        commit_sha="abc1234",
        scan_date=date.today(),
        tool_version="0.1.0",
    )
    base.update(meta_overrides)
    meta = ReportMeta(**base)
    return ScanReport(meta=meta, findings=[], scope_ledger=ScopeLedger())


def _render(scan_report, agent_output):
    from repo_audit.render.renderer import (
        _compute_critical_render_classes,
        _make_env,
        build_deterministic_exec_header,
    )

    env = _make_env()
    tmpl = env.get_template("state_report.md.j2")
    return tmpl.render(
        report=scan_report,
        agent_output=agent_output,
        deterministic_exec_header=build_deterministic_exec_header(scan_report.findings),
        critical_render_classes=_compute_critical_render_classes(scan_report),
        trend=None,
    )


# Distinctive, digit-free sentinel so the assertion is unambiguously about the
# macro rendering prose, never about numbers.
_SENTINEL = "Authentication paths look well isolated across the auth module."


def test_dimension_narrative_renders_when_present():
    """A present narrative renders inside its own dimension section (## 3. Security & SAST).

    This is the regression test for the loop-scoping bug: it fails against the
    buggy loop-local macro and passes with the namespace fix.
    """
    from repo_audit.agent.schema import AgentScanReport, DimensionNarrative

    agent_output = AgentScanReport(
        dimensions=[
            DimensionNarrative(dimension="security", narrative=_SENTINEL),
        ],
    )
    scan_report = _scan_report(agent_status="ok")

    md = _render(scan_report, agent_output)

    # The narrative text must appear at all.
    assert _SENTINEL in md, "narrative sentinel missing — loop-scoping bug not fixed"

    # ...and it must appear inside the Security section: after the
    # `## 3. Security & SAST` heading and before the next `## ` heading.
    heading = "## 3. Security & SAST"
    heading_idx = md.index(heading)
    sentinel_idx = md.index(_SENTINEL)
    assert sentinel_idx > heading_idx, "sentinel rendered before the Security heading"

    next_heading_idx = md.index("\n## ", heading_idx + len(heading))
    assert sentinel_idx < next_heading_idx, "sentinel leaked past the Security section"


def test_dimension_narrative_fallback_when_no_match():
    """No matching narrative + agent_status != 'ok' → the per-dimension fallback marker renders."""
    from repo_audit.agent.schema import AgentScanReport

    # No security narrative present (empty dimensions); agent reports unavailable.
    agent_output = AgentScanReport(dimensions=[])
    scan_report = _scan_report(agent_status="unavailable_network")

    md = _render(scan_report, agent_output)

    assert "AI narrative unavailable" in md
    assert "unavailable_network" in md
