"""scan_runner cross-stack run_quality_depth wiring (Plan 15-04, Task 2).

Proves the run_quality_depth wiring (mirrors test_scan_runner_architecture.py):

  * ``run_scan`` calls ``scan_runner.run_quality_depth`` (via ``_THIS_MODULE``,
    monkeypatchable), passing the already-computed ``detection`` stack tags as
    ``stacks`` and threading ``qd_build``; its findings fold into the merged
    report's ``quality`` dimension; a "Quality-depth" disclosure note joins
    ``scope_ledger.notes``.
  * a ``not_applicable`` (no live_url AND no RN surface) step is DISCLOSED but does
    NOT flip ``meta.partial`` (the first-class degrade, via
    ``_phase11_step_degraded``).
  * an APPLICABLE degradation (``unavailable``) DOES flip ``meta.partial``.
  * ``--qd-build`` threads ``qd_build=True`` into run_quality_depth (and a fleet
    sweep / default leaves it False).

These run the deterministic pipeline with ``--no-agent`` (the root conftest
autouse fixture keeps the agent loop a hermetic no-op) and monkeypatch
``scan_runner.run_quality_depth`` so no axe / lighthouse / metro binary is touched.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.architecture import ArchitectureScanResult
from repo_audit.adapters.cicd import CicdScanResult
from repo_audit.adapters.mobile import MobileScanResult
from repo_audit.adapters.quality_depth import QualityDepthScanResult
from repo_audit.adapters.sast import SastScanResult
from repo_audit.adapters.sca import ScaScanResult
from repo_audit.adapters.supabase import SupabaseScanResult
from repo_audit.adapters.supply_chain import SupplyChainResult
from repo_audit.adapters.test_depth import TestDepthScanResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport

pytestmark = pytest.mark.skipif(
    not hasattr(scan_runner, "run_quality_depth"),
    reason="Plan 15-04 not yet landed — scan_runner.run_quality_depth missing",
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
    """Stub every OTHER cross-stack step to a default ``ok`` result so partial is
    governed SOLELY by run_quality_depth."""
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


def _qd_finding(tool: str, rule_id: str) -> Finding:
    return Finding(
        dimension="quality",  # type: ignore[arg-type]
        severity="info",
        confidence="candidate",
        evidence_type="runtime",
        source_tool=tool,
        source_collector="quality_depth",
        rule_id=rule_id,
        recommendation="verify the structural signal",
        evidence=Evidence(
            tool=tool, output_snippet=f"{tool} finding",
            parsed_value={"rule_id": rule_id},
        ),
    )


def test_run_scan_calls_run_quality_depth(fake_repo_on_disk, monkeypatch):
    """run_scan calls run_quality_depth; its findings fold into the quality dim."""
    seen = {"calls": 0}

    def _spy(repo_path, *, base_env, stacks, qd_build,
             prior_web_bytes=None, prior_rn_bytes=None):
        seen["calls"] += 1
        seen["base_env"] = base_env
        seen["stacks"] = stacks
        seen["qd_build"] = qd_build
        return QualityDepthScanResult(
            findings=[_qd_finding("axe", "color-contrast")],
            status="ok",
            notes="Quality-depth ok: 1 finding(s)",
        )

    monkeypatch.setattr(scan_runner, "run_quality_depth", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert seen["calls"] == 1
    assert isinstance(seen["base_env"], dict)
    assert isinstance(seen["stacks"], list)
    assert seen["qd_build"] is False  # default; never built without --qd-build
    qd_findings = [
        f for f in result.scan_report.findings
        if f.source_collector == "quality_depth"
    ]
    assert {f.source_tool for f in qd_findings} == {"axe"}
    assert all(f.dimension == "quality" for f in qd_findings)
    assert "quality-depth" in (result.scan_report.scope_ledger.notes or "").lower()


def test_not_applicable_does_not_flip_partial(fake_repo_on_disk, monkeypatch):
    """A not_applicable run_quality_depth does NOT flip meta.partial."""
    _neutralize_other_steps(monkeypatch)

    monkeypatch.setattr(
        scan_runner, "run_quality_depth",
        lambda repo_path, *, base_env, stacks, qd_build,
        prior_web_bytes=None, prior_rn_bytes=None: QualityDepthScanResult(
            status="not_applicable",
            notes="Quality-depth not applicable: no web surface and no RN surface",
        ),
        raising=True,
    )

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    assert result.scan_report.meta.partial is False
    assert "quality-depth" in (result.scan_report.scope_ledger.notes or "").lower()


def test_applicable_unavailable_flips_partial(fake_repo_on_disk, monkeypatch):
    """An applicable run_quality_depth degradation (unavailable) DOES flip partial."""
    _neutralize_other_steps(monkeypatch)

    monkeypatch.setattr(
        scan_runner, "run_quality_depth",
        lambda repo_path, *, base_env, stacks, qd_build,
        prior_web_bytes=None, prior_rn_bytes=None: QualityDepthScanResult(
            status="unavailable",
            notes="Quality-depth degraded",
            ledger_notes=["axe (unavailable): @axe-core/cli not found"],
        ),
        raising=True,
    )

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.scan_report.meta.partial is True
    assert "quality-depth" in (result.scan_report.scope_ledger.notes or "").lower()


def test_qd_build_threads_through(fake_repo_on_disk, monkeypatch):
    """--qd-build threads qd_build=True into run_quality_depth."""
    seen = {}

    def _spy(repo_path, *, base_env, stacks, qd_build,
             prior_web_bytes=None, prior_rn_bytes=None):
        seen["qd_build"] = qd_build
        return QualityDepthScanResult(status="not_applicable")

    monkeypatch.setattr(scan_runner, "run_quality_depth", _spy, raising=True)

    scan_runner.run_scan(fake_repo_on_disk, no_agent=True, qd_build=True)

    assert seen["qd_build"] is True


# --- Plan 15-05: scan_runner reads the prior sidecar + extracts carrier bytes ---
#
# These prove the EXTRACTION/WIRING layer: run_quality_depth is monkeypatched
# WHOLESALE (the real composite reachability is proven in
# test_run_quality_depth.py); here we assert scan_runner reads the prior sidecar
# and passes the prior carrier bytes that the SHARED trend extractors
# (_web_transfer_metric / _rn_bundle_metric) yield from the prior ScanReport.

from datetime import date, timedelta


def _carrier_lighthouse(web_transfer_bytes: int) -> Finding:
    return Finding(
        dimension="quality",  # type: ignore[arg-type]
        severity="info",
        evidence_type="runtime",
        confidence="candidate",
        source_tool="lighthouse",
        source_collector="quality_depth",
        rule_id="lighthouse_perf_summary",
        recommendation="verify the transfer size before acting",
        evidence=Evidence(
            tool="lighthouse",
            parsed_value={"web_transfer_bytes": web_transfer_bytes},
        ),
    )


def _carrier_metro(rn_bundle_bytes: int) -> Finding:
    return Finding(
        dimension="quality",  # type: ignore[arg-type]
        severity="info",
        evidence_type="static",
        confidence="candidate",
        source_tool="metro",
        source_collector="quality_depth",
        rule_id="rn_bundle_size_summary",
        recommendation="verify against your release artifact before acting",
        evidence=Evidence(
            tool="metro", parsed_value={"rn_bundle_bytes": rn_bundle_bytes}
        ),
    )


def _write_prior_sidecar(repo_path, findings, *, days_ago=1):
    """Write a REAL prior ScanReport sidecar so find_prior_sidecar resolves it."""
    prior_date = date.today() - timedelta(days=days_ago)
    meta = ReportMeta(
        repo_slug="prior-fake",
        commit_sha="UNCOMMITTED",
        scan_date=prior_date,
        tool_version="0.0.0-test",
    )
    report = ScanReport(schema_version="1", meta=meta, findings=findings)
    out_dir = repo_path / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"prior-fake-state-report-{prior_date.isoformat()}.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


def test_prior_sidecar_bytes_passed_into_run_quality_depth(
    fake_repo_on_disk, monkeypatch
):
    """scan_runner extracts prior web/RN carrier bytes from the prior sidecar via
    the shared trend extractors and threads them into run_quality_depth."""
    _neutralize_other_steps(monkeypatch)
    _write_prior_sidecar(
        fake_repo_on_disk,
        [_carrier_lighthouse(200_000), _carrier_metro(400_000)],
    )

    seen = {}

    def _spy(repo_path, *, base_env, stacks, qd_build,
             prior_web_bytes=None, prior_rn_bytes=None):
        seen["prior_web_bytes"] = prior_web_bytes
        seen["prior_rn_bytes"] = prior_rn_bytes
        return QualityDepthScanResult(status="not_applicable")

    monkeypatch.setattr(scan_runner, "run_quality_depth", _spy, raising=True)

    scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    # The exact byte values from the prior sidecar's carriers, extracted via
    # _web_transfer_metric / _rn_bundle_metric (NOT a second reader).
    assert seen["prior_web_bytes"] == 200_000
    assert seen["prior_rn_bytes"] == 400_000


def test_no_prior_sidecar_passes_none_prior_bytes(fake_repo_on_disk, monkeypatch):
    """No prior sidecar (baseline run) → prior bytes resolve to None (no fabricated
    baseline)."""
    _neutralize_other_steps(monkeypatch)
    # Deliberately write NO prior sidecar.

    seen = {}

    def _spy(repo_path, *, base_env, stacks, qd_build,
             prior_web_bytes=None, prior_rn_bytes=None):
        seen["prior_web_bytes"] = prior_web_bytes
        seen["prior_rn_bytes"] = prior_rn_bytes
        return QualityDepthScanResult(status="not_applicable")

    monkeypatch.setattr(scan_runner, "run_quality_depth", _spy, raising=True)

    scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert seen["prior_web_bytes"] is None
    assert seen["prior_rn_bytes"] is None


def test_corrupt_prior_sidecar_degrades_prior_bytes_to_none(
    fake_repo_on_disk, monkeypatch
):
    """A prior sidecar that parses but whose carrier is absent → None prior bytes;
    a corrupt prior must never crash the scan."""
    _neutralize_other_steps(monkeypatch)
    # A valid prior report with NO size carriers at all → both extract to None.
    _write_prior_sidecar(fake_repo_on_disk, [])

    seen = {}

    def _spy(repo_path, *, base_env, stacks, qd_build,
             prior_web_bytes=None, prior_rn_bytes=None):
        seen["prior_web_bytes"] = prior_web_bytes
        seen["prior_rn_bytes"] = prior_rn_bytes
        return QualityDepthScanResult(status="not_applicable")

    monkeypatch.setattr(scan_runner, "run_quality_depth", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0  # never crashes
    assert seen["prior_web_bytes"] is None
    assert seen["prior_rn_bytes"] is None
