"""BYO adapter pipeline-flow proof (D-06-08 / SC-6 / BYO-01).

These pin the two halves of the BYO contract:
- A disabled/unattested tool NEVER runs (returns 'unavailable' and never even
  opens its SARIF file — the gate short-circuits first).
- An enabled+attested synthetic 'commercial' tool routes its SARIF through the
  SAME ``sarif_to_findings`` the 8 OSS tools use, producing schema-valid
  Findings tagged ``source_tool='acme-scanner'``, with the 06-01 candidate cap
  applied uniformly (a tool-reported error/9.x => severity='major' +
  confidence='candidate' + caveat, faithful 'critical' in evidence).

importorskip keeps these SKIPPED until both modules land, then ACTIVE
(Phase 3 discipline; not xfail-strict).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("repo_audit.adapters.sarif")
byo_pkg = pytest.importorskip("repo_audit.adapters.byo")

from repo_audit.adapters.byo import ByoToolConfig, run_byo_tool  # noqa: E402

_FIXTURE = Path(__file__).parent / "fixtures" / "acme_commercial.sarif"


def _cfg(**overrides) -> ByoToolConfig:
    base = {
        "name": "acme-scanner",
        "sarif_output": "out.sarif",
        "default_dimension": "security",
    }
    base.update(overrides)
    return ByoToolConfig(**base)


def _stage_fixture(repo: Path, rel: str = "out.sarif") -> None:
    dest = repo / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_FIXTURE, dest)


# --- gate: disabled/unattested never runs --------------------------------


def test_disabled_tool_returns_unavailable_without_running(tmp_path: Path):
    """A should_run=False cfg returns 'unavailable' and never reads its SARIF.

    sarif_output points at a path that does NOT exist; if the gate failed to
    short-circuit, the read would raise/leak. status='unavailable', zero
    findings, and the reason names the attestation gate.
    """
    cfg = _cfg(enabled=True, use_rights_attestation=False, sarif_output="nope.sarif")
    assert cfg.should_run is False

    result = run_byo_tool(cfg, tmp_path)

    assert result.status == "unavailable"
    assert result.findings == []
    assert result.source_tool == "acme-scanner"
    # The gate (attestation) — NOT a file-not-found — is the reason.
    assert "attestation" in result.notes.lower()
    assert not (tmp_path / "nope.sarif").exists()  # nothing was created/touched


def test_missing_sarif_for_enabled_tool_is_unavailable_not_raise(tmp_path: Path):
    """An enabled+attested tool whose SARIF is absent => 'unavailable', no raise."""
    cfg = _cfg(enabled=True, use_rights_attestation=True, sarif_output="absent.sarif")

    result = run_byo_tool(cfg, tmp_path)

    assert result.status == "unavailable"
    assert result.findings == []
    assert "not found" in result.notes.lower()


# --- the SC-6 proof: synthetic commercial tool into the Finding pipeline --


def test_synthetic_commercial_flows_into_findings(tmp_path: Path):
    """SC-6: an arbitrary SARIF-emitting commercial tool flows through the SAME
    pipeline as OSS, producing source_tool-tagged schema-valid Findings."""
    _stage_fixture(tmp_path)
    cfg = _cfg(enabled=True, use_rights_attestation=True, sarif_output="out.sarif")

    result = run_byo_tool(cfg, tmp_path)

    assert result.status == "ok"
    assert result.source_adapter == "byo"
    assert result.source_tool == "acme-scanner"
    assert len(result.findings) == 2

    # Every finding is tagged with the BYO tool's name (BYO-01 traceability).
    assert all(f.source_tool == "acme-scanner" for f in result.findings)
    # SARIF tools are static analysers; candidate pre-verification (06-01).
    assert all(f.evidence_type == "static" for f in result.findings)
    assert all(f.confidence == "candidate" for f in result.findings)
    # The fixture's dimension fallback is the cfg default.
    assert all(f.dimension == "security" for f in result.findings)


def test_critical_result_capped_to_major_with_caveat(tmp_path: Path):
    """The 06-01 contract holds for BYO: a tool-reported error/9.3-band result
    surfaces as severity='major' + confidence='candidate' + caveat, with the
    faithful 'critical' preserved in evidence (NOT a critical Finding)."""
    _stage_fixture(tmp_path)
    cfg = _cfg(enabled=True, use_rights_attestation=True, sarif_output="out.sarif")

    result = run_byo_tool(cfg, tmp_path)

    sqli = next(f for f in result.findings if f.rule_id == "ACME-SQLI-001")
    # BINDING contract: NOT a critical Finding — capped at candidate rung.
    assert sqli.severity == "major"
    assert sqli.confidence == "candidate"
    assert sqli.confidence_caveat
    assert "acme-scanner" in sqli.confidence_caveat
    # Faithful signal preserved for Phase-17 promotion.
    assert sqli.evidence.parsed_value["faithful_severity"] == "critical"
    assert sqli.file == "src/db/users.py"
    assert sqli.line == 42


def test_byo_uses_same_function_as_oss(tmp_path: Path, monkeypatch):
    """run_byo_tool calls the SAME repo_audit.adapters.sarif.sarif_to_findings
    the 8 OSS tools use — no forked parse path (spy on the shared symbol)."""
    import repo_audit.adapters.byo.adapter as byo_adapter
    import repo_audit.adapters.sarif as sarif_pkg

    calls: list[str] = []
    real = sarif_pkg.sarif_to_findings

    def _spy(doc, **kwargs):
        calls.append(kwargs.get("source_tool", ""))
        return real(doc, **kwargs)

    # Patch the name the adapter actually resolves at call time.
    monkeypatch.setattr(byo_adapter, "sarif_to_findings", _spy)

    _stage_fixture(tmp_path)
    cfg = _cfg(enabled=True, use_rights_attestation=True, sarif_output="out.sarif")
    run_byo_tool(cfg, tmp_path)

    assert calls == ["acme-scanner"]
    # Identity: the adapter's symbol IS the package's shared function.
    assert real is sarif_pkg.parser.sarif_to_findings
