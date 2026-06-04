"""scan_runner cross-stack run_cicd wiring (Plan 13-04, Task 2).

Proves the five-part run_cicd wiring (mirrors the run_supply_chain wiring in the
same file):

  * ``run_scan`` calls ``scan_runner.run_cicd`` (via ``_THIS_MODULE``) and its
    findings fold into the merged report; a "CI/CD" disclosure note joins
    ``scope_ledger.notes``.
  * a ``not_applicable`` (no CI/CD files) step is DISCLOSED but does NOT flip
    ``meta.partial`` (D-13-05, via ``_phase11_step_degraded``).
  * an APPLICABLE degradation (``unavailable`` / tool absent when files present)
    DOES flip ``meta.partial``.
  * the read-only contract holds: post-flight ``git status --porcelain`` on the
    target repo is empty after a CI/CD scan (checkov's SARIF lands in the
    scan_tempdir, not the repo).

These run the deterministic pipeline with ``--no-agent`` (the root conftest
autouse fixture keeps the agent loop a hermetic no-op) and monkeypatch
``scan_runner.run_cicd`` so no zizmor / actionlint / hadolint / checkov binary is
touched.

Function names (``test_run_scan_calls_run_cicd`` /
``test_no_cicd_files_does_not_flip_partial``) match 13-VALIDATION.md and the plan
spec; do NOT rename.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.cicd import CicdScanResult, run_cicd as _real_run_cicd
from repo_audit.adapters.mobile import MobileScanResult
from repo_audit.adapters.sast import SastScanResult
from repo_audit.adapters.sca import ScaScanResult
from repo_audit.adapters.supabase import SupabaseScanResult
from repo_audit.adapters.supply_chain import SupplyChainResult
from repo_audit.adapters.test_depth import TestDepthScanResult
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding

pytestmark = pytest.mark.skipif(
    not hasattr(scan_runner, "run_cicd"),
    reason="Wave 2 (Plan 04) not yet landed — scan_runner.run_cicd missing",
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

    The partial-flag tests assert ``meta.partial is False`` on a not_applicable
    CI/CD step, so partial must be governed SOLELY by run_cicd — not by the real
    run_sca / run_supply_chain / run_supabase / run_mobile / run_sast / Phase-11
    steps degrading because osv / syft / detekt / etc. are absent on this host.
    Each result dataclass defaults to ``status='ok'`` with no findings.
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


def _cicd_finding() -> Finding:
    """A workflow-security finding the spy returns from run_cicd."""
    return Finding(
        dimension="security",
        severity="major",
        confidence="candidate",
        evidence_type="static",
        source_tool="zizmor",
        source_collector="cicd",
        rule_id="template-injection",
        recommendation="quote the expression",
        evidence=Evidence(
            tool="zizmor",
            output_snippet="template injection in ci.yml",
            parsed_value={"rule_id": "template-injection"},
        ),
    )


def test_run_scan_calls_run_cicd(fake_repo_on_disk, monkeypatch):
    """run_scan calls scan_runner.run_cicd; its finding folds + 'ci/cd' hits ledger."""
    seen = {"calls": 0}

    def _spy(repo_path, *, base_env):
        seen["calls"] += 1
        seen["base_env"] = base_env
        return CicdScanResult(
            findings=[_cicd_finding()],
            status="ok",
            notes="CI/CD ok: 1 finding(s)",
        )

    monkeypatch.setattr(scan_runner, "run_cicd", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    # The spy was called exactly once, with a base_env (the scan_tempdir env).
    assert seen["calls"] == 1
    assert isinstance(seen["base_env"], dict)
    # The CI/CD finding folded into the merged report.
    merged = result.scan_report.findings
    assert any(
        f.source_tool == "zizmor" and f.rule_id == "template-injection"
        for f in merged
    )
    # A "CI/CD" disclosure note joined the scope ledger.
    assert "ci/cd" in (result.scan_report.scope_ledger.notes or "").lower()


def test_no_cicd_files_does_not_flip_partial(fake_repo_on_disk, monkeypatch):
    """A not_applicable run_cicd (no CI/CD files) does NOT flip meta.partial (D-13-05)."""
    _neutralize_other_steps(monkeypatch)

    def _spy(repo_path, *, base_env):
        return CicdScanResult(
            findings=[],
            status="not_applicable",
            notes="CI/CD not applicable: no .github/workflows, Dockerfile, or IaC config",
            ledger_notes=[
                "zizmor (unavailable): no .github/workflows present — zizmor not applicable",
            ],
        )

    monkeypatch.setattr(scan_runner, "run_cicd", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    assert result.scan_report is not None
    # A no-files / not_applicable step is disclosed but is NOT an applicable
    # degradation — _phase11_step_degraded swallows it.
    assert result.scan_report.meta.partial is False
    # ...but it IS disclosed in the ledger.
    assert "ci/cd" in (result.scan_report.scope_ledger.notes or "").lower()


def test_applicable_degradation_flips_partial(fake_repo_on_disk, monkeypatch):
    """An applicable run_cicd degradation (unavailable) DOES flip meta.partial."""
    _neutralize_other_steps(monkeypatch)

    def _spy(repo_path, *, base_env):
        return CicdScanResult(
            findings=[],
            status="unavailable",
            notes="CI/CD degraded",
            ledger_notes=["zizmor (unavailable): zizmor not found (vendor + PATH miss)"],
        )

    monkeypatch.setattr(scan_runner, "run_cicd", _spy, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.scan_report.meta.partial is True
    assert "ci/cd" in (result.scan_report.scope_ledger.notes or "").lower()


def test_read_only_contract(fake_repo_on_disk, monkeypatch):
    """Post-flight git status on the target repo is empty after a CI/CD scan.

    Runs the REAL run_cicd (no monkeypatch). On a host where the four tools are
    absent every sub-collector degrades to unavailable — and crucially checkov's
    SARIF (when checkov IS present) lands in the scan_tempdir, never the repo. The
    target tree must be byte-for-byte unchanged.
    """
    # Use the real composite so the real checkov tempdir path is exercised.
    monkeypatch.setattr(scan_runner, "run_cicd", _real_run_cicd, raising=True)

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    # The scan_runner post-flight tripwire is the AUTHORITATIVE read-only check:
    # it diffs pre/post git status and reports any file modified OUTSIDE
    # docs/state-reports/. checkov's SARIF lands in the scan_tempdir, so nothing
    # in the target tree should change.
    assert result.offenders == []
    porcelain = subprocess.run(
        ["git", "-C", str(fake_repo_on_disk), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # Belt-and-braces over the tripwire: only the docs/ sidecar tree may appear
    # (git reports the untracked dir as ``?? docs/``); the repo root, .github, and
    # any IaC are untouched — no CI/CD tool artifact (e.g. results_sarif.sarif)
    # leaked into the target tree.
    offending = [
        ln
        for ln in porcelain.splitlines()
        if ln.strip() and "docs/" not in ln and "docs/state-reports" not in ln
    ]
    assert offending == [], f"unexpected target-repo writes: {offending}"
