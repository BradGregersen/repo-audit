"""run_cicd composite-envelope contract (Plan 13-04, Task 1).

Activated (the Plan-01 ``skipif`` opens the instant ``cicd.run_cicd`` lands).
These tests drive the never-raising composite envelope:

  * the no-CI/CD-surface case degrades to a NON-partial-flipping disposition
    (``not_applicable``) without raising (D-13-05 first-class degrade);
  * a tool-absent (``unavailable``) sub-result while files ARE present is an
    APPLICABLE degradation, distinct from the no-files case;
  * a sub-collector ``timeout`` rolls up to ``timeout``;
  * a sub-collector raising unexpectedly is caught (the composite still returns);
  * findings merge in the fixed order zizmor + actionlint + hadolint + checkov,
    deterministically across repeated calls;
  * the sub-collectors are monkeypatchable on the package namespace.

Function names (``test_no_surface_all_unavailable`` / ``test_tool_absent_degrades`` /
``test_tool_timeout_degrades``) match 13-VALIDATION.md and must NOT be renamed.
"""
from __future__ import annotations

import pytest

import repo_audit.adapters.cicd as cicd
from repo_audit.schema.finding import Evidence, Finding

pytestmark = pytest.mark.skipif(
    not hasattr(cicd, "run_cicd"),
    reason="Wave 2 (Plan 04) not yet landed — cicd.run_cicd missing",
)


def _finding(tool: str, dimension: str = "security") -> Finding:
    """A minimal candidate/static finding tagged with its source tool."""
    return Finding(
        dimension=dimension,  # type: ignore[arg-type]
        severity="minor",
        confidence="candidate",
        evidence_type="static",
        source_tool=tool,
        rule_id=f"{tool}-rule",
        evidence=Evidence(
            tool=tool,
            output_snippet=f"{tool} finding",
            parsed_value={"rule_id": f"{tool}-rule"},
        ),
    )


# Lightweight stand-in result envelopes (every sub-collector returns
# findings/status/notes — Zizmor/Actionlint/Hadolint/Checkov all share the shape).
class _Stub:
    def __init__(self, findings=None, status="ok", notes=""):
        self.findings = list(findings or [])
        self.status = status
        self.notes = notes


def _patch_all(monkeypatch, *, zizmor, actionlint, hadolint, checkov):
    monkeypatch.setattr(cicd, "collect_zizmor", lambda *a, **k: zizmor, raising=True)
    monkeypatch.setattr(
        cicd, "collect_actionlint", lambda *a, **k: actionlint, raising=True
    )
    monkeypatch.setattr(
        cicd, "collect_hadolint", lambda *a, **k: hadolint, raising=True
    )
    monkeypatch.setattr(cicd, "collect_checkov", lambda *a, **k: checkov, raising=True)


def test_no_surface_all_unavailable(fake_cicd_repo, monkeypatch):
    """No workflows/Dockerfile/IaC -> not_applicable, no findings, never raises."""
    repo = fake_cicd_repo(workflows=False, dockerfile=False, iac=False)
    # Each collector reports the no-files reason ("not applicable").
    _patch_all(
        monkeypatch,
        zizmor=_Stub(status="unavailable", notes="no .github/workflows present — zizmor not applicable"),
        actionlint=_Stub(status="unavailable", notes="no .github/workflows present — actionlint not applicable"),
        hadolint=_Stub(status="unavailable", notes="no Dockerfile present — hadolint not applicable"),
        checkov=_Stub(status="unavailable", notes="no IaC config present — checkov not applicable"),
    )

    result = cicd.run_cicd(repo, base_env={})

    assert result.findings == []
    # No-files is NON-partial-flipping (D-13-05): not_applicable, not unavailable.
    assert result.status == "not_applicable"
    # Per-surface disclosure note.
    assert len(result.ledger_notes) == 4
    assert any("zizmor" in n for n in result.ledger_notes)
    assert any("checkov" in n for n in result.ledger_notes)


def test_tool_absent_degrades(fake_cicd_repo, monkeypatch):
    """A tool absent WHILE files present -> applicable degradation 'unavailable'."""
    repo = fake_cicd_repo(workflows=True, dockerfile=False, iac=False)
    _patch_all(
        monkeypatch,
        # workflows present but zizmor binary missing -> applicable unavailable.
        zizmor=_Stub(status="unavailable", notes="zizmor not found (vendor + PATH miss)"),
        actionlint=_Stub(findings=[_finding("actionlint", "process")], status="ok", notes="actionlint: 1 finding(s)"),
        hadolint=_Stub(status="unavailable", notes="no Dockerfile present — hadolint not applicable"),
        checkov=_Stub(status="unavailable", notes="no IaC config present — checkov not applicable"),
    )

    result = cicd.run_cicd(repo, base_env={})

    # An applicable degradation (tool absent while files present) -> unavailable,
    # distinct from the all-not-applicable case above.
    assert result.status == "unavailable"
    # The actionlint finding still folds in.
    assert any(f.source_tool == "actionlint" for f in result.findings)
    # The tool-absent reason is disclosed and distinct from a timeout reason.
    assert any("not found" in n for n in result.ledger_notes)
    assert not any("exceeded" in n for n in result.ledger_notes)


def test_tool_timeout_degrades(fake_cicd_repo, monkeypatch):
    """A sub-collector timeout rolls up to 'timeout', reason distinct from absent."""
    repo = fake_cicd_repo(workflows=True, dockerfile=True, iac=False)
    _patch_all(
        monkeypatch,
        zizmor=_Stub(status="ok", notes="zizmor: 0 finding(s)"),
        actionlint=_Stub(status="ok", notes="actionlint: 0 finding(s)"),
        hadolint=_Stub(status="timeout", notes="hadolint exceeded 120s on Dockerfile"),
        checkov=_Stub(status="unavailable", notes="no IaC config present — checkov not applicable"),
    )

    result = cicd.run_cicd(repo, base_env={})

    # Any timeout dominates the roll-up.
    assert result.status == "timeout"
    # The timeout reason is DISTINCT from a tool-absent "not found" reason (FND-04).
    assert any("exceeded" in n for n in result.ledger_notes)
    assert not any("not found" in n for n in result.ledger_notes)


def test_all_ok_merges_in_fixed_order(fake_cicd_repo, monkeypatch):
    """All ok -> status ok, findings merge zizmor+actionlint+hadolint+checkov."""
    repo = fake_cicd_repo(workflows=True, dockerfile=True, iac=True)
    _patch_all(
        monkeypatch,
        zizmor=_Stub(findings=[_finding("zizmor")], status="ok"),
        actionlint=_Stub(findings=[_finding("actionlint", "process")], status="ok"),
        hadolint=_Stub(findings=[_finding("hadolint")], status="ok"),
        checkov=_Stub(findings=[_finding("checkov")], status="ok"),
    )

    result = cicd.run_cicd(repo, base_env={})

    assert result.status == "ok"
    assert [f.source_tool for f in result.findings] == [
        "zizmor",
        "actionlint",
        "hadolint",
        "checkov",
    ]
    # No degrade notes when every sub-step is ok.
    assert result.ledger_notes == []


def test_deterministic_across_calls(fake_cicd_repo, monkeypatch):
    """Repeated calls produce an identical (deterministic) findings order."""
    repo = fake_cicd_repo(workflows=True, dockerfile=True, iac=True)
    _patch_all(
        monkeypatch,
        zizmor=_Stub(findings=[_finding("zizmor")], status="ok"),
        actionlint=_Stub(findings=[_finding("actionlint", "process")], status="ok"),
        hadolint=_Stub(findings=[_finding("hadolint")], status="ok"),
        checkov=_Stub(findings=[_finding("checkov")], status="ok"),
    )

    first = [f.source_tool for f in cicd.run_cicd(repo, base_env={}).findings]
    second = [f.source_tool for f in cicd.run_cicd(repo, base_env={}).findings]
    assert first == second


def test_sub_collector_raise_is_caught(fake_cicd_repo, monkeypatch):
    """A sub-collector raising unexpectedly is caught; the composite still returns."""
    repo = fake_cicd_repo(workflows=True, dockerfile=False, iac=False)

    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cicd, "collect_zizmor", _boom, raising=True)
    monkeypatch.setattr(
        cicd,
        "collect_actionlint",
        lambda *a, **k: _Stub(findings=[_finding("actionlint", "process")], status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        cicd,
        "collect_hadolint",
        lambda *a, **k: _Stub(status="unavailable", notes="no Dockerfile present — hadolint not applicable"),
        raising=True,
    )
    monkeypatch.setattr(
        cicd,
        "collect_checkov",
        lambda *a, **k: _Stub(status="unavailable", notes="no IaC config present — checkov not applicable"),
        raising=True,
    )

    # Must not raise.
    result = cicd.run_cicd(repo, base_env={})
    # The crashed step folds to an applicable degradation (unavailable).
    assert result.status == "unavailable"
    assert any("zizmor" in n and "RuntimeError" in n for n in result.ledger_notes)
    # The healthy actionlint finding still folds in.
    assert any(f.source_tool == "actionlint" for f in result.findings)


def test_run_cicd_reexports_subcollectors():
    """The four sub-collectors + run_cicd + CicdScanResult are importable."""
    for name in (
        "collect_zizmor",
        "collect_actionlint",
        "collect_hadolint",
        "collect_checkov",
        "run_cicd",
        "CicdScanResult",
    ):
        assert hasattr(cicd, name), f"cicd.{name} not re-exported"
