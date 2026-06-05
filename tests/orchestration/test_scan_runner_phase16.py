"""scan_runner Phase-16 dynamic/deep-lane wiring tests (Plan 16-07).

Proves the orchestration-level wiring of the five Phase-16 lanes
(``run_e2e`` / ``run_fuzz`` / ``run_codeql`` / ``run_dast`` /
``run_byo_commercial``) WITHOUT touching a live tool — every lane is
monkeypatched on the ``scan_runner`` module (the same patchable-attribute
discipline the Phase-11 wiring tests use):

  * ``test_lanes_dispatched_and_merged`` — all 5 lanes are dispatched during
    run_scan and their findings appear in the merged set in deterministic order.
  * ``test_e2e_fuzz_flags_threaded`` — ``--e2e`` / ``--fuzz`` flow through to
    ``run_e2e`` / ``run_fuzz`` as ``opt_in``; the default run passes opt_in=False.
  * ``test_not_applicable_does_not_flip_partial`` — a lane returning
    ``not_applicable`` does NOT flip ``ScanResult.partial``; an applicable
    degradation (``partial``) DOES.
  * ``test_dast_runtime_assertion`` — a DAST stub returning a runtime-tagged
    finding is CAUGHT/FOLDED at the runner level: ``run_scan`` still returns a
    ScanResult (no AssertionError propagates), the runtime-tagged finding is
    DROPPED from the merged set, and a SAFE-01 violation note is recorded in the
    ledger (D-16-12 tripwire wired at the runner level, never crashing — D-25).

These run the deterministic pipeline with ``--no-agent`` (the root conftest
``_stub_agent_session`` autouse fixture keeps the agent loop a hermetic no-op).
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.architecture import ArchitectureScanResult
from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.byo.commercial import CommercialScanResult
from repo_audit.adapters.cicd import CicdScanResult
from repo_audit.adapters.dast import _SOURCE_TOOL as _DAST_SOURCE_TOOL
from repo_audit.adapters.dast import DastResult
from repo_audit.adapters.e2e import E2eScanResult
from repo_audit.adapters.fuzz import FuzzScanResult
from repo_audit.adapters.mobile import MobileScanResult
from repo_audit.adapters.quality_depth import QualityDepthScanResult
from repo_audit.adapters.sast import SastScanResult
from repo_audit.adapters.sca import ScaScanResult
from repo_audit.adapters.supabase import SupabaseScanResult
from repo_audit.adapters.supply_chain import SupplyChainResult
from repo_audit.adapters.test_depth import TestDepthScanResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding


def _neutralize_other_steps(monkeypatch):
    """Stub every NON-Phase-16 cross-stack step to a non-flipping result so the
    scan's ``partial`` flag is governed SOLELY by the Phase-16 lanes (mirrors the
    quality-depth wiring tests' ``_neutralize_other_steps``)."""
    monkeypatch.setattr(
        scan_runner, "run_sca",
        lambda repo_path, *, base_env, refresh=False: ScaScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_supply_chain",
        lambda repo_path, *, base_env, scan_date, working_tree_findings, sca_findings: (
            SupplyChainResult(status="ok")
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_cicd",
        lambda repo_path, *, base_env: CicdScanResult(status="not_applicable"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_architecture",
        lambda repo_path, *, base_env, stacks: ArchitectureScanResult(
            status="not_applicable"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_quality_depth",
        lambda repo_path, *, base_env, stacks, qd_build,
        prior_web_bytes=None, prior_rn_bytes=None: QualityDepthScanResult(
            status="not_applicable"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_supabase",
        lambda repo_path, *, base_env, rls_pgrls=False, rls_runtime=False: (
            SupabaseScanResult(status="ok")
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_mobile",
        lambda repo_path, *, base_env, mobsf=False, mobsf_build=False, apk=None: (
            MobileScanResult(status="ok")
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_sast",
        lambda repo_path, *, base_env, detection: SastScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_kotlin",
        lambda repo_path, *, base_env, attempt_typed=True: TestDepthScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_expo",
        lambda repo_path, *, base_env: TestDepthScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_test_depth",
        lambda repo_path, **kwargs: TestDepthScanResult(status="ok"),
        raising=True,
    )


@pytest.fixture
def fake_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot / post-flight checks work."""
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    return tmp_path


def _lane_finding(source_tool: str, rule_id: str, *, evidence_type: str = "static") -> Finding:
    """A minimal candidate-confidence finding stamped with a per-lane source_tool."""
    return Finding(
        dimension="security",
        severity="major",
        evidence_type=evidence_type,  # type: ignore[arg-type]
        confidence="candidate",
        source_tool=source_tool,
        source_collector="phase16_wiring_test",
        rule_id=rule_id,
        recommendation=f"{source_tool} finding for {rule_id}.",
        evidence=Evidence(
            tool=source_tool,
            output_snippet=f"{source_tool}: {rule_id}",
            parsed_value={},
        ),
    )


def _patch_phase16_lanes(
    monkeypatch,
    *,
    e2e=None,
    fuzz=None,
    codeql=None,
    dast=None,
    byo=None,
):
    """Monkeypatch all five Phase-16 lanes on the scan_runner module.

    A None argument defaults the lane to a benign non-flipping stub (a
    not_applicable dataclass lane / an unavailable AdapterResult lane) so a test
    can override only the lane(s) it cares about.
    """
    monkeypatch.setattr(
        scan_runner, "run_e2e",
        e2e or (lambda repo, **kw: E2eScanResult(status="not_applicable")),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_fuzz",
        fuzz or (lambda repo, **kw: FuzzScanResult(status="not_applicable")),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_codeql",
        codeql or (lambda repo, **kw: AdapterResult(status="unavailable")),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_dast",
        dast or (lambda repo, **kw: DastResult(status="unavailable")),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_byo_commercial",
        byo or (lambda repo, **kw: CommercialScanResult(status="not_applicable")),
        raising=True,
    )


# --- 1. all 5 lanes dispatched + findings merged in deterministic order -----


def test_lanes_dispatched_and_merged(fake_repo_on_disk, monkeypatch):
    """All 5 lanes are called during run_scan and their findings merge in order.

    Each lane stub records that it was called and returns exactly one finding
    tagged with its own source_tool. The merged finding set must contain all 5
    in the deterministic dispatch order (e2e, fuzz, codeql, dast, byo).
    """
    called: list[str] = []

    def _e2e(repo, **kw):
        called.append("e2e")
        return E2eScanResult(status="ok", findings=[_lane_finding("e2e-harness", "e2e_pass")])

    def _fuzz(repo, **kw):
        called.append("fuzz")
        return FuzzScanResult(status="ok", findings=[_lane_finding("atheris", "fuzz_signal")])

    def _codeql(repo, **kw):
        called.append("codeql")
        return AdapterResult(status="ok", findings=[_lane_finding("codeql", "cq_taint")])

    def _dast(repo, **kw):
        called.append("dast")
        return DastResult(status="ok", findings=[_lane_finding(_DAST_SOURCE_TOOL, "zap_alert")])

    def _byo(repo, **kw):
        called.append("byo")
        return CommercialScanResult(status="ok", findings=[_lane_finding("snyk", "commercial")])

    _neutralize_other_steps(monkeypatch)
    _patch_phase16_lanes(monkeypatch, e2e=_e2e, fuzz=_fuzz, codeql=_codeql, dast=_dast, byo=_byo)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    # All 5 lanes dispatched.
    assert set(called) == {"e2e", "fuzz", "codeql", "dast", "byo"}

    # All 5 lane findings present in the merged set.
    merged_tools = [f.source_tool for f in result.scan_report.findings]
    for tool in ("e2e-harness", "atheris", "codeql", _DAST_SOURCE_TOOL, "snyk"):
        assert tool in merged_tools, f"{tool} finding missing from merged set"

    # Phase 17 (Plan 17-03): the verification stage (run_verification) now sits
    # between the findings merge and the report assembly, and its stage-1
    # tiered_corroborate re-sorts the finding set DETERMINISTICALLY by
    # build_finding_ref (SC-5 — order is independent of dispatch/input order). So
    # the FINAL report order is the deterministic finding_ref order, NOT the
    # dispatch order. We assert the order is the stable finding_ref sort (the
    # report's authoritative final order) rather than the now-obsolete dispatch
    # order. Presence of all 5 lanes (above) is what the dispatch contract needs;
    # determinism is the SC-5 guarantee.
    from repo_audit.verification.record import build_finding_ref

    final_refs = [build_finding_ref(f) for f in result.scan_report.findings]
    assert final_refs == sorted(final_refs), (
        "post-verification report findings must be in deterministic "
        f"finding_ref order (SC-5): {final_refs}"
    )


# --- 2. --e2e / --fuzz flags thread to run_e2e / run_fuzz opt_in ------------


def test_e2e_fuzz_flags_threaded(fake_repo_on_disk, monkeypatch):
    """``e2e=True`` / ``fuzz=True`` reach run_e2e / run_fuzz as opt_in; default False."""
    seen = {"e2e_opt_in": None, "fuzz_opt_in": None}

    def _e2e(repo, **kw):
        seen["e2e_opt_in"] = kw.get("opt_in")
        return E2eScanResult(status="not_applicable")

    def _fuzz(repo, **kw):
        seen["fuzz_opt_in"] = kw.get("opt_in")
        return FuzzScanResult(status="not_applicable")

    # --- flags ON ---
    _neutralize_other_steps(monkeypatch)
    _patch_phase16_lanes(monkeypatch, e2e=_e2e, fuzz=_fuzz)
    scan_runner.run_scan(fake_repo_on_disk, no_agent=True, e2e=True, fuzz=True)
    assert seen["e2e_opt_in"] is True
    assert seen["fuzz_opt_in"] is True

    # --- defaults OFF (a fleet sweep never opts the heavy lanes in) ---
    seen["e2e_opt_in"] = seen["fuzz_opt_in"] = None
    _patch_phase16_lanes(monkeypatch, e2e=_e2e, fuzz=_fuzz)
    scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert seen["e2e_opt_in"] is False
    assert seen["fuzz_opt_in"] is False


# --- 3. not_applicable does NOT flip partial; an applicable degradation DOES -


def test_not_applicable_does_not_flip_partial(fake_repo_on_disk, monkeypatch):
    """A not_applicable lane is disclosed but non-flipping; partial does flip."""
    # All lanes not_applicable / unavailable (off) → no Phase-16-driven partial.
    _neutralize_other_steps(monkeypatch)
    _patch_phase16_lanes(monkeypatch)
    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.rc == 0
    assert result.scan_report.meta.partial is False

    # A dataclass lane that ACTUALLY RAN and degraded (status='partial') flips.
    _neutralize_other_steps(monkeypatch)
    _patch_phase16_lanes(
        monkeypatch,
        e2e=lambda repo, **kw: E2eScanResult(status="partial", notes="harness run failed"),
    )
    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.rc == 0
    assert result.scan_report.meta.partial is True


# --- 4. DAST runtime tripwire: caught + folded at the runner level -----------


def test_dast_runtime_assertion(fake_repo_on_disk, monkeypatch):
    """A runtime-tagged DAST finding is DROPPED + folded — run_scan still returns.

    Proves the scan-runner-level SAFE-01 / D-16-12 guard: the runtime-tagged
    finding is excluded from the merged set, a SAFE-01 violation note is recorded
    in the ledger, and NO AssertionError propagates (D-25 never-raise contract).
    """
    runtime_finding = _lane_finding(
        _DAST_SOURCE_TOOL, "zap_runtime_breach", evidence_type="runtime"
    )
    safe_finding = _lane_finding(_DAST_SOURCE_TOOL, "zap_static_ok")

    def _dast(repo, **kw):
        # A DAST result that (incorrectly) carries a runtime-tagged finding.
        return DastResult(status="ok", findings=[runtime_finding, safe_finding])

    _neutralize_other_steps(monkeypatch)
    _patch_phase16_lanes(monkeypatch, dast=_dast)

    # MUST NOT raise — the guarded assert is caught at the runner level.
    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)
    assert result.rc == 0

    merged = result.scan_report.findings
    # The runtime-tagged DAST finding was DROPPED from the merged set.
    assert not any(
        f.source_tool == _DAST_SOURCE_TOOL and f.evidence_type == "runtime"
        for f in merged
    ), "runtime-tagged DAST finding must be dropped from the merged set"
    # The benign static DAST finding survives.
    assert any(
        f.source_tool == _DAST_SOURCE_TOOL and f.rule_id == "zap_static_ok"
        for f in merged
    ), "non-runtime DAST finding must survive the guard"
    # A SAFE-01 violation note is recorded in the ledger.
    assert "SAFE-01" in (result.scan_report.scope_ledger.notes or "")
