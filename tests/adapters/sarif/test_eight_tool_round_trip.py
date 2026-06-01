"""FND-01 / SC-1: the 8-tool recorded SARIF corpus round-trips through ONE parser.

This is the recorded-fixture discipline from Phase 3 (the 33 frozen TypeScript
triples) applied to SARIF. A frozen `sample.sarif` for each of the 8 tools
(osv-scanner, semgrep, mobsfscan, detekt, zizmor, hadolint, checkov,
dependency-cruiser; provenance in `fixtures/PROVENANCE.md`) is fed through the
SAME `sarif_to_findings` function — the parametrization is the proof of SC-1's
"same function, only severity_map + default_dimension differ" claim.

Binding contract (Plan 06-01, REVISED 2026-06-01 DI-06-01-01 Option A):
a tool-reported critical/blocker does NOT surface as a critical Finding. It
surfaces as severity="major" + confidence="candidate" + a non-empty
confidence_caveat, with the faithful severity preserved in
evidence.parsed_value["faithful_severity"]. There are NO candidate+critical
Findings. These assertions therefore never expect severity=="critical".

The module-gate `importorskip` flips this whole file SKIPPED -> ACTIVE the moment
Plan 06-01's parser lands (Phase 3 discipline). NOT xfail-strict.
"""
from __future__ import annotations

import pytest

# Module-gate (Phase 3 discipline): skip cleanly if Plan 06-01 hasn't landed.
sarif_mod = pytest.importorskip("repo_audit.adapters.sarif")
sarif_to_findings = sarif_mod.sarif_to_findings

from repo_audit.schema.finding import Finding  # noqa: E402

from tests.adapters.sarif.conftest import SARIF_TOOLS, TOOL_CONFIG  # noqa: E402


@pytest.fixture
def findings_for(load_sarif):
    """Parse a tool's recorded fixture through the single generic parser."""

    def _run(tool: str) -> list[Finding]:
        cfg = TOOL_CONFIG[tool]
        return sarif_to_findings(
            load_sarif(tool),
            source_tool=tool,
            default_dimension=cfg.dim,
            severity_map=cfg.map,
        )

    return _run


@pytest.mark.parametrize("tool", SARIF_TOOLS)
def test_round_trips_through_same_function(tool, findings_for):
    """SC-1: all 8 fixtures parse via the SAME sarif_to_findings without raising.

    The parametrization over the 8 tools IS the proof that only the per-tool
    (default_dimension, severity_map) differs — the function under test is one.
    """
    findings = findings_for(tool)
    assert findings, f"{tool}: recorded fixture produced no findings"
    assert all(isinstance(f, Finding) for f in findings)


@pytest.mark.parametrize("tool", SARIF_TOOLS)
def test_every_finding_tagged_source_tool(tool, findings_for):
    """BYO-01: every Finding traces back to its source_tool (Phase 17 prereq)."""
    findings = findings_for(tool)
    assert all(f.source_tool == tool for f in findings)
    assert all(f.evidence.tool == tool for f in findings)


@pytest.mark.parametrize("tool", SARIF_TOOLS)
def test_every_finding_schema_valid(tool, findings_for):
    """SAFE-01 / SCH-04 hold against REAL tool output, not just hand-built dicts.

    Construction already enforces the schema (a returned Finding is valid by
    definition). The load-bearing extra assertion: NO Finding is candidate+critical
    (SCH-04 absolute), and any capped faithful critical/blocker carries the
    non-empty confidence_caveat breadcrumb with its faithful severity preserved —
    the Plan 06-01 cap path proven against real corpus output.
    """
    findings = findings_for(tool)
    for f in findings:
        # SCH-04 absolute: candidate + {critical, blocker} is structurally impossible.
        assert not (f.confidence == "candidate" and f.severity in {"critical", "blocker"})
        faithful = f.evidence.parsed_value.get("faithful_severity")
        if faithful in {"critical", "blocker"}:
            # Capped to major at the candidate rung, with the Phase-17 breadcrumb.
            assert f.severity == "major"
            assert f.confidence == "candidate"
            assert f.confidence_caveat is not None
            assert f.confidence_caveat.strip() != ""
            # Faithful signal preserved for Phase-17 promotion.
            assert f.evidence.parsed_value["faithful_severity"] == faithful


@pytest.mark.parametrize("tool", SARIF_TOOLS)
def test_dimension_defaults_to_caller_supplied(tool, findings_for):
    """D-06-05: SARIF gives no dimension signal -> caller's default is used."""
    cfg = TOOL_CONFIG[tool]
    findings = findings_for(tool)
    assert all(f.dimension == cfg.dim for f in findings)


def test_corpus_covers_all_eight_named_tools():
    """The corpus is exactly the 8 named tools — guards against silent drops."""
    assert set(SARIF_TOOLS) == {
        "osv-scanner",
        "semgrep",
        "mobsfscan",
        "detekt",
        "zizmor",
        "hadolint",
        "checkov",
        "dependency-cruiser",
    }


def test_corpus_exercises_the_candidate_cap_caveat_path():
    """At least one tool's real output drives a faithful critical/blocker.

    Proves the cap+caveat path (D-06-02) is exercised by the corpus, not just by
    hand-built dicts in test_sarif_to_findings.py.
    """
    import json
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    saw_cap = False
    for tool in SARIF_TOOLS:
        cfg = TOOL_CONFIG[tool]
        doc = json.loads((fixtures / tool / "sample.sarif").read_text())
        for f in sarif_to_findings(
            doc, source_tool=tool, default_dimension=cfg.dim, severity_map=cfg.map
        ):
            if f.evidence.parsed_value.get("faithful_severity") in {"critical", "blocker"}:
                assert f.severity == "major" and f.confidence_caveat
                saw_cap = True
    assert saw_cap, "no recorded fixture exercises the candidate severity cap"
