"""scan_runner cross-stack test-depth wiring tests (Plan 11-07).

Proves:
  * B3 — under ``--refresh-coverage`` + ``--mutation`` on a node (typescript-node)
    repo, the executed node lcov line coverage is THREADED into
    ``scan_runner.run_test_depth`` as ``injected_line_pct`` so the D-11-06 WEAK
    signal can fire for node stacks whose in-step coverage tier is gated OFF.
  * the node coverage runner (``_maybe_refresh_coverage``) is invoked AT MOST ONCE
    per scan for the node + mutation path (no double coverage run).
  * W1 — a not-applicable kotlin/expo step does NOT flip the scan to ``partial``;
    a genuinely-degraded applicable step still does.
  * W5 — scan_runner shares the single ``_NODE_STACKS`` source with refresh.

These run the deterministic pipeline with ``--no-agent`` (the root conftest
``_stub_agent_session`` autouse fixture keeps the agent loop a hermetic no-op too)
and monkeypatch the cross-stack steps so no real binary / network is touched.
"""
from __future__ import annotations

import subprocess

import pytest

from repo_audit.adapters.test_depth import TestDepthScanResult
from repo_audit.adapters.typescript import refresh as _refresh_mod
from repo_audit.orchestration import scan_runner
from repo_audit.schema.finding import Evidence, Finding


def _node_coverage_finding(line_pct: float) -> Finding:
    """A node lcov aggregate coverage Finding (source_tool=lcov, rule=coverage_summary)."""
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="static",
        confidence="candidate",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_summary",
        recommendation=f"{line_pct}% line coverage executed.",
        evidence=Evidence(
            tool="lcov",
            output_snippet=f"lcov: {line_pct}% line",
            parsed_value={"line_pct": line_pct, "total_pct": line_pct},
        ),
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


def _force_node_primary(monkeypatch, repo_path):
    """Make detect_stacks report a single typescript-node primary stack."""
    from repo_audit.schema.detection import DetectionResult, StackProfile

    detection = DetectionResult(
        stacks=[StackProfile(stack="typescript-node", root_dir=repo_path)]
    )
    monkeypatch.setattr(scan_runner, "detect_stacks", lambda repo: detection)


# --- B3: node lcov line_pct threaded into run_test_depth -------------------


def test_node_lcov_line_pct_threaded_into_run_test_depth(fake_repo_on_disk, monkeypatch):
    """B3: --refresh-coverage + --mutation on a node repo threads the node line_pct.

    ``_maybe_refresh_coverage`` injects a node ``coverage_summary`` Finding with
    line_pct=88.0; the run_test_depth spy records the ``injected_line_pct`` kwarg ==
    88.0 (the executed node coverage reaches the mutation tier). Fails on the
    pre-change code where the node line_pct never reached run_test_depth.
    """
    _force_node_primary(monkeypatch, fake_repo_on_disk)

    refresh_calls = {"n": 0}

    def _inject_node_coverage(repo_path, findings):
        refresh_calls["n"] += 1
        return list(findings) + [_node_coverage_finding(88.0)]

    monkeypatch.setattr(scan_runner, "_maybe_refresh_coverage", _inject_node_coverage)

    spy = {"injected": "UNSET"}

    def _spy_run_test_depth(repo_path, *, base_env, **kwargs):
        spy["injected"] = kwargs.get("injected_line_pct", "MISSING")
        return TestDepthScanResult(status="ok")

    monkeypatch.setattr(scan_runner, "run_test_depth", _spy_run_test_depth, raising=True)
    monkeypatch.setattr(
        scan_runner, "run_kotlin",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_expo",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )

    scan_runner.run_scan(
        fake_repo_on_disk, no_agent=True, refresh_coverage=True, mutation=True
    )

    assert spy["injected"] == 88.0
    # Double-run guard: the node coverage refresh fires AT MOST ONCE per scan.
    assert refresh_calls["n"] == 1


def test_no_double_coverage_run_node_mutation(fake_repo_on_disk, monkeypatch):
    """B3 guard: _maybe_refresh_coverage runs at most once for the node+mutation path."""
    _force_node_primary(monkeypatch, fake_repo_on_disk)

    refresh_calls = {"n": 0}

    def _count_refresh(repo_path, findings):
        refresh_calls["n"] += 1
        return list(findings) + [_node_coverage_finding(75.0)]

    monkeypatch.setattr(scan_runner, "_maybe_refresh_coverage", _count_refresh)
    monkeypatch.setattr(
        scan_runner, "run_test_depth",
        lambda repo, **kw: TestDepthScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_kotlin",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_expo",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )

    scan_runner.run_scan(
        fake_repo_on_disk, no_agent=True, refresh_coverage=True, mutation=True
    )

    assert refresh_calls["n"] == 1


# --- W1: not-applicable does not force partial; degraded still does ---------


def _stub_all_steps_ok(monkeypatch):
    """Stub the NON-Phase-11 cross-stack steps to ok so the partial flag tracks
    ONLY the Phase-11 (kotlin/expo/test_depth) statuses the test sets.

    The real walker + collectors + adapters run on the bare committed
    ``fake_repo_on_disk`` (all report ok / empty there), so they contribute
    nothing to partial — only the cross-stack steps below could, and they are
    pinned ok.
    """
    from dataclasses import dataclass, field as _field

    from repo_audit.adapters.sast import SastScanResult

    @dataclass
    class _OkRes:
        status: str = "ok"
        findings: list = _field(default_factory=list)
        feed_provenance: list = _field(default_factory=list)
        ledger_notes: list = _field(default_factory=list)
        notes: str = ""

    # The forced typescript-node detection makes run_adapters run the TS adapter
    # tiers, which self-report `unavailable` on a bare repo (no tsc/eslint) — an
    # UNRELATED degradation. Stub it empty so partial tracks only the Phase-11 steps.
    monkeypatch.setattr(scan_runner, "run_adapters", lambda repo, det: [])
    monkeypatch.setattr(scan_runner, "run_sca", lambda repo, **kw: _OkRes(), raising=True)
    monkeypatch.setattr(scan_runner, "run_supabase", lambda repo, **kw: _OkRes(), raising=True)
    monkeypatch.setattr(scan_runner, "run_mobile", lambda repo, **kw: _OkRes(), raising=True)
    monkeypatch.setattr(
        scan_runner, "run_sast",
        lambda repo, **kw: SastScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(scan_runner, "_maybe_refresh_coverage", lambda r, f: f)


def test_not_applicable_kotlin_expo_no_partial(fake_repo_on_disk, monkeypatch):
    """W1: a pure-TS repo where kotlin/expo are not_applicable → partial is False.

    Every applicable step is ok; kotlin/expo self-report ``not_applicable`` (no
    gradle, no Expo). The scan must NOT flip to partial just because those steps
    don't apply. Fails on the pre-change code (status != 'ok' → partial=True).
    """
    _force_node_primary(monkeypatch, fake_repo_on_disk)
    _stub_all_steps_ok(monkeypatch)

    monkeypatch.setattr(
        scan_runner, "run_test_depth",
        lambda repo, **kw: TestDepthScanResult(status="ok"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_kotlin",
        lambda repo, **kw: TestDepthScanResult(
            status="not_applicable",
            ledger_notes=["Kotlin/detekt not applicable: no gradle build files"],
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_expo",
        lambda repo, **kw: TestDepthScanResult(
            status="not_applicable",
            ledger_notes=["Expo not applicable: no app.json / expo dep"],
        ),
        raising=True,
    )

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.rc == 0
    assert result.scan_report.meta.partial is False


def test_genuine_degradation_still_flips_partial(fake_repo_on_disk, monkeypatch):
    """W1: an APPLICABLE step reporting unavailable still sets partial True.

    Proves the gate distinguishes not-applicable from genuinely-degraded: a node
    test_depth step that reports ``unavailable`` (e.g. a coverage runner failed)
    still flips partial even though kotlin/expo are not_applicable.
    """
    _force_node_primary(monkeypatch, fake_repo_on_disk)
    _stub_all_steps_ok(monkeypatch)

    monkeypatch.setattr(
        scan_runner, "run_test_depth",
        lambda repo, **kw: TestDepthScanResult(
            status="unavailable", notes="coverage runner failed"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_kotlin",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )
    monkeypatch.setattr(
        scan_runner, "run_expo",
        lambda repo, **kw: TestDepthScanResult(status="not_applicable"),
        raising=True,
    )

    result = scan_runner.run_scan(fake_repo_on_disk, no_agent=True)

    assert result.scan_report.meta.partial is True


# --- W1: the partial-determination predicate (unit) ------------------------


def test_phase11_step_degraded_predicate():
    """ok / not_applicable are non-degrading; everything else degrades partial."""
    assert scan_runner._phase11_step_degraded("ok") is False
    assert scan_runner._phase11_step_degraded("not_applicable") is False
    assert scan_runner._phase11_step_degraded("unavailable") is True
    assert scan_runner._phase11_step_degraded("partial") is True
    assert scan_runner._phase11_step_degraded("timeout") is True


# --- W5: single _NODE_STACKS source ----------------------------------------


def test_node_stacks_single_source():
    """W5: scan_runner reads the SAME _NODE_STACKS object as refresh (no duplicate)."""
    assert scan_runner._NODE_STACKS is _refresh_mod._NODE_STACKS
