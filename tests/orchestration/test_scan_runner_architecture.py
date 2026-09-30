"""scan_runner cross-stack run_architecture wiring (Plan 14-04, Task 2).

Proves the four-part run_architecture wiring (mirrors the run_cicd wiring in
``test_scan_runner_cicd.py``):

  * ``run_scan`` calls ``scan_runner.run_architecture`` (via ``_THIS_MODULE``),
    passing the already-computed ``detection`` stack tags as ``stacks`` (detection
    is NOT re-run inside the adapter); its findings fold into the merged report's
    ``architecture_rot`` dimension; an "Architecture" disclosure note joins
    ``scope_ledger.notes``.
  * a ``not_applicable`` (non-JS stack — no JS/TS dependency graph) step is
    DISCLOSED but does NOT flip ``meta.partial`` (the first-class degrade, via
    ``_phase11_step_degraded``).
  * an APPLICABLE degradation (``unavailable`` / a tool absent on a JS stack)
    DOES flip ``meta.partial``.
  * the read-only contract holds: post-flight ``git status --porcelain`` on the
    target repo is empty after an architecture scan (depcruise's shipped ruleset
    + jscpd's JSON report land in the scan_tempdir, not the repo).

These run the deterministic pipeline with ``--no-agent`` (the root conftest
autouse fixture keeps the agent loop a hermetic no-op) and monkeypatch
``scan_runner.run_architecture`` so no dependency-cruiser / jscpd binary is
touched.

Function names match the 14-04 plan spec; do NOT rename.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.architecture import (
    ArchitectureScanResult,
    run_architecture as _real_run_architecture,
)
from repo_audit.adapters.cicd import CicdScanResult
from repo_audit.adapters.mobile import MobileScanResult
from repo_audit.adapters.sast import SastScanResult
from repo_audit.adapters.sca import ScaScanResult
from repo_audit.adapters.supabase import SupabaseScanResult
from repo_audit.adapters.supply_chain import SupplyChainResult
from repo_audit.adapters.test_depth import TestDepthScanResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding

pytestmark = pytest.mark.skipif(
    not hasattr(scan_runner, "run_architecture"),
    reason="Wave 3 (Plan 04) not yet landed — scan_runner.run_architecture missing",
)


@pytest.fixture
def fake_repo_on_disk(tmp_path):
    """A minimal git repo so run_scan's git snapshot / post-flight checks work."""
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-q", "-m", "init",
        ],
        check=True,
    )
    return tmp_path


def _neutralize_other_steps(monkeypatch):
    """Stub every OTHER cross-stack step to a default ``ok`` result.

    The partial-flag tests assert ``meta.partial`` is governed SOLELY by
    run_architecture — not by the real run_sca / run_supply_chain / run_supabase /
    run_mobile / run_sast / run_cicd / Phase-11 steps degrading because osv / syft /
    detekt / etc. are absent on this host. Each result dataclass defaults to
    ``status='ok'`` with no findings.
    """
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
        lambda repo_path, *, base_env, attempt_typed=True, gradle_roots=(): TestDepthScanResult(status="ok"),
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


def _arch_finding(tool: str, rule_id: str) -> Finding:
    """An architecture_rot finding the spy returns from run_architecture."""
    return Finding(
        dimension="architecture_rot",  # type: ignore[arg-type]
        severity="minor",
        confidence="candidate",
        evidence_type="static",
        source_tool=tool,
        source_collector="architecture",
        rule_id=rule_id,
        recommendation="candidate: review the structural signal",
        evidence=Evidence(
            tool=tool,
            output_snippet=f"{tool} finding",
            parsed_value={"rule_id": rule_id},
        ),
    )


def test_run_scan_calls_run_architecture(fake_repo_on_disk, monkeypatch):
    """run_scan calls run_architecture; BOTH findings fold into architecture_rot."""
    seen = {"calls": 0}

    def _spy(repo_path, *, base_env, stacks):
        seen["calls"] += 1
        seen["base_env"] = base_env
        seen["stacks"] = stacks
        return ArchitectureScanResult(
            findings=[
                _arch_finding("dependency-cruiser", "no-circular"),
                _arch_finding("jscpd", "duplication_summary"),
            ],
            status="ok",
            notes="Architecture ok: 2 finding(s)",
        )

    monkeypatch.setattr(scan_runner, "run_architecture", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    # The spy was called exactly once, with a base_env (the scan_tempdir env) and
    # a stacks list (the reused detection tags — detection NOT re-run in the adapter).
    assert seen["calls"] == 1
    assert isinstance(seen["base_env"], dict)
    assert isinstance(seen["stacks"], list)
    # BOTH architecture findings folded into the architecture_rot dimension.
    arch_findings = [
        f for f in result.scan_report.findings if f.dimension == "architecture_rot"
    ]
    tools = {f.source_tool for f in arch_findings}
    assert {"dependency-cruiser", "jscpd"} <= tools
    # An "Architecture" disclosure note joined the scope ledger.
    assert "architecture" in (result.scan_report.scope_ledger.notes or "").lower()


def test_non_js_stack_does_not_flip_partial(fake_repo_on_disk, monkeypatch):
    """A not_applicable run_architecture (non-JS stack) does NOT flip meta.partial."""
    _neutralize_other_steps(monkeypatch)

    def _spy(repo_path, *, base_env, stacks):
        return ArchitectureScanResult(
            findings=[],
            status="not_applicable",
            notes="Architecture not applicable: no JS/TS dependency graph stack",
        )

    monkeypatch.setattr(scan_runner, "run_architecture", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    assert result.scan_report is not None
    # A non-JS / not_applicable step is disclosed but is NOT an applicable
    # degradation — _phase11_step_degraded swallows it.
    assert result.scan_report.meta.partial is False
    # ...but it IS disclosed in the ledger.
    assert "architecture" in (result.scan_report.scope_ledger.notes or "").lower()


def test_applicable_degradation_flips_partial(fake_repo_on_disk, monkeypatch):
    """An applicable run_architecture degradation (unavailable) DOES flip partial."""
    _neutralize_other_steps(monkeypatch)

    def _spy(repo_path, *, base_env, stacks):
        return ArchitectureScanResult(
            findings=[],
            status="unavailable",
            notes="Architecture degraded",
            ledger_notes=[
                "dependency-cruiser (unavailable): depcruise not found (node_modules + PATH miss)",
            ],
        )

    monkeypatch.setattr(scan_runner, "run_architecture", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.scan_report.meta.partial is True
    assert "architecture" in (result.scan_report.scope_ledger.notes or "").lower()


def test_read_only_contract(fake_repo_on_disk, monkeypatch):
    """Post-flight git status on the target repo is empty after an architecture scan.

    Runs the REAL run_architecture (no monkeypatch). The fake repo has no
    package.json / JS stack, so the composite degrades to not_applicable WITHOUT
    invoking either tool; even when a tool IS present, depcruise's shipped ruleset
    + jscpd's JSON report land in the scan_tempdir, never the repo. The target tree
    must be byte-for-byte unchanged.
    """
    monkeypatch.setattr(scan_runner, "run_architecture", _real_run_architecture, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    # The scan_runner post-flight tripwire is the AUTHORITATIVE read-only check.
    assert result.offenders == []
    porcelain = subprocess.run(
        ["git", "-C", str(fake_repo_on_disk), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # Only the docs/ sidecar tree may appear; the repo root is untouched — no
    # architecture tool artifact (shipped ruleset / jscpd-report.json) leaked.
    offending = [
        ln
        for ln in porcelain.splitlines()
        if ln.strip() and "docs/" not in ln and "docs/state-reports" not in ln
    ]
    assert offending == [], f"unexpected target-repo writes: {offending}"
