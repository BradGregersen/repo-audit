"""run_architecture composite-envelope contract (Plan 14-04, Wave-3).

Activated the instant ``architecture.run_architecture`` lands (the Plan-01
``skipif`` gate, mirroring ``tests/adapters/cicd/test_run_cicd.py``). These tests
drive the never-raising composite envelope:

  * a non-JS-stack repo degrades to a NON-partial-flipping disposition
    (``not_applicable``) without raising (the first-class degrade);
  * a sub-collector ``timeout`` rolls up to ``timeout`` (dominates);
  * a tool-absent (``unavailable``) sub-result while a JS stack IS present is an
    APPLICABLE degradation → ``unavailable``;
  * a sub-collector raising unexpectedly is caught (the composite still returns);
  * findings merge in the fixed order circular (depcruise) + duplication (jscpd),
    deterministically across repeated calls;
  * the sub-collectors are monkeypatchable on the package namespace;
  * per-sub-step disclosure folds into ``ledger_notes`` (SAFE-08).
"""
from __future__ import annotations

import pytest

import repo_audit.adapters.architecture as architecture
from repo_audit.schema.finding import Evidence, Finding

pytestmark = pytest.mark.skipif(
    not hasattr(architecture, "run_architecture"),
    reason="Wave 3 (Plan 04) not yet landed — architecture.run_architecture missing",
)


def _finding(tool: str) -> Finding:
    """A minimal candidate/static architecture finding tagged with its tool."""
    return Finding(
        dimension="architecture_rot",  # type: ignore[arg-type]
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


class _Stub:
    """A stand-in sub-collector result (findings/status/notes shape)."""

    def __init__(self, findings=None, status="ok", notes=""):
        self.findings = list(findings or [])
        self.status = status
        self.notes = notes


def _patch(monkeypatch, *, circular, duplication):
    monkeypatch.setattr(
        architecture, "collect_dependency_cruiser", lambda *a, **k: circular, raising=True
    )
    monkeypatch.setattr(
        architecture, "collect_jscpd", lambda *a, **k: duplication, raising=True
    )


def test_non_js_stack_not_applicable(monkeypatch, fake_repo_on_disk) -> None:
    """No JS stack → not_applicable, sub-collectors never invoked, never raises."""
    result = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["kotlin-android"]
    )
    assert result.status == "not_applicable"
    assert result.findings == []


def test_timeout_dominates(monkeypatch, fake_repo_on_disk) -> None:
    """Any sub-step timeout → composite timeout."""
    _patch(
        monkeypatch,
        circular=_Stub(status="timeout", notes="depcruise timed out"),
        duplication=_Stub(status="ok"),
    )
    result = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["typescript-node"]
    )
    assert result.status == "timeout"


def test_applicable_degrade_unavailable(monkeypatch, fake_repo_on_disk) -> None:
    """A tool-absent sub-result while a JS stack IS present → unavailable."""
    _patch(
        monkeypatch,
        circular=_Stub(status="unavailable", notes="depcruise absent"),
        duplication=_Stub(status="ok"),
    )
    result = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["expo"]
    )
    assert result.status == "unavailable"
    assert any("depcruise" in n for n in result.ledger_notes)


def test_findings_merge_in_stable_order(monkeypatch, fake_repo_on_disk) -> None:
    """Findings merge circular (depcruise) then duplication (jscpd), deterministically."""
    _patch(
        monkeypatch,
        circular=_Stub(findings=[_finding("dependency-cruiser")]),
        duplication=_Stub(findings=[_finding("jscpd")]),
    )
    r1 = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["react-native"]
    )
    r2 = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["react-native"]
    )
    tools1 = [f.source_tool for f in r1.findings]
    assert tools1 == ["dependency-cruiser", "jscpd"]
    assert tools1 == [f.source_tool for f in r2.findings]


def test_sub_collector_exception_is_caught(monkeypatch, fake_repo_on_disk) -> None:
    """An unexpected sub-collector exception is caught — composite still returns."""

    def _boom(*a, **k):
        raise RuntimeError("depcruise blew up")

    monkeypatch.setattr(
        architecture, "collect_dependency_cruiser", _boom, raising=True
    )
    monkeypatch.setattr(
        architecture, "collect_jscpd", lambda *a, **k: _Stub(status="ok"), raising=True
    )

    result = architecture.run_architecture(
        fake_repo_on_disk, base_env={}, stacks=["typescript-node"]
    )
    assert result.status in {"unavailable", "timeout"}
    assert result.findings == []
