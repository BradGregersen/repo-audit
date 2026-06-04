"""run_quality_depth composite envelope (Plan 15-04, Task 2).

Proves the composite mirrors run_architecture: a no-surface GATE (no live_url AND
no RN surface) short-circuits to ``not_applicable`` WITHOUT invoking any tool; a
crashing sub-collector folds to ``unavailable`` (never raises); the status
roll-up order holds; findings accumulate across sub-steps. Every sub-collector is
read OFF the package namespace so the tests monkeypatch on ``quality_depth.*``.
"""
from __future__ import annotations

import pytest

from repo_audit.adapters import quality_depth
from repo_audit.adapters.quality_depth import (
    AxeResult,
    LighthouseResult,
    QualityDepthScanResult,
    RnBundleResult,
    run_quality_depth,
)
from repo_audit.adapters.quality_depth.config import QualityDepthConfig
from repo_audit.schema.finding import Evidence, Finding


def _qd_finding(tool: str, rule_id: str) -> Finding:
    return Finding(
        dimension="quality",  # type: ignore[arg-type]
        severity="info",
        confidence="candidate",
        evidence_type="runtime" if tool != "metro" else "static",
        source_tool=tool,
        source_collector="quality_depth",
        rule_id=rule_id,
        recommendation="verify this signal before acting",
        evidence=Evidence(
            tool=tool, output_snippet=f"{tool} finding",
            parsed_value={"rule_id": rule_id},
        ),
    )


def _patch_config(monkeypatch, *, live_url=None):
    """Patch the composite's config read so no .repo-audit.yaml is needed."""
    monkeypatch.setattr(
        quality_depth, "read_quality_depth_config",
        lambda repo_path: QualityDepthConfig(live_url=live_url),
        raising=True,
    )


def test_no_surface_gate_invokes_no_collector(tmp_path, monkeypatch):
    """No live_url AND no RN surface → not_applicable with ZERO collector calls."""
    _patch_config(monkeypatch, live_url=None)
    spy = {"axe": 0, "lighthouse": 0, "rn_bundle": 0}

    def _axe(*a, **k):
        spy["axe"] += 1
        return AxeResult(status="ok")

    def _lh(*a, **k):
        spy["lighthouse"] += 1
        return LighthouseResult(status="ok")

    def _rn(*a, **k):
        spy["rn_bundle"] += 1
        return RnBundleResult(status="ok")

    monkeypatch.setattr(quality_depth, "collect_axe", _axe, raising=True)
    monkeypatch.setattr(quality_depth, "collect_lighthouse", _lh, raising=True)
    monkeypatch.setattr(quality_depth, "collect_rn_bundle", _rn, raising=True)

    result = run_quality_depth(
        tmp_path, base_env={}, stacks=["python"], qd_build=False
    )

    assert result.status == "not_applicable"
    assert spy == {"axe": 0, "lighthouse": 0, "rn_bundle": 0}
    assert result.findings == []


def test_crashing_collector_folds_to_unavailable(tmp_path, monkeypatch):
    """A sub-collector that RAISES never propagates — folds to unavailable."""
    _patch_config(monkeypatch, live_url="https://example.test")

    def _boom(*a, **k):
        raise RuntimeError("axe blew up")

    monkeypatch.setattr(quality_depth, "collect_axe", _boom, raising=True)
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        lambda *a, **k: LighthouseResult(status="ok"),
        raising=True,
    )
    # No RN surface → rn_bundle is not invoked (skipped, not crashed).
    monkeypatch.setattr(
        quality_depth, "collect_rn_bundle",
        lambda *a, **k: RnBundleResult(status="ok"),
        raising=True,
    )

    result = run_quality_depth(tmp_path, base_env={}, stacks=["python"])

    # An applicable crashed step flips the composite to unavailable; never raises.
    assert result.status == "unavailable"
    assert any("axe" in n for n in result.ledger_notes)


def test_findings_accumulate_in_stable_order(tmp_path, monkeypatch):
    """ok sub-steps accumulate findings; status rolls up to ok."""
    _patch_config(monkeypatch, live_url="https://example.test")

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        lambda *a, **k: AxeResult(
            findings=[_qd_finding("axe", "color-contrast")], status="ok"
        ),
        raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        lambda *a, **k: LighthouseResult(
            findings=[_qd_finding("lighthouse", "lighthouse_perf_summary")],
            status="ok",
        ),
        raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_rn_bundle",
        lambda *a, **k: RnBundleResult(
            findings=[_qd_finding("metro", "rn_bundle_size_summary")], status="ok"
        ),
        raising=True,
    )

    # An RN surface present (expo) → rn_bundle IS invoked too.
    result = run_quality_depth(tmp_path, base_env={}, stacks=["expo"])

    assert result.status == "ok"
    tools = [f.source_tool for f in result.findings]
    assert tools == ["axe", "lighthouse", "metro"]  # stable merge order


def test_rn_only_surface_runs_rn_skips_web(tmp_path, monkeypatch):
    """No live_url but an RN surface → rn_bundle runs, axe/lighthouse skipped."""
    _patch_config(monkeypatch, live_url=None)
    spy = {"axe": 0, "lighthouse": 0, "rn_bundle": 0}

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        lambda *a, **k: (spy.__setitem__("axe", spy["axe"] + 1)
                         or AxeResult(status="ok")),
        raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        lambda *a, **k: (spy.__setitem__("lighthouse", spy["lighthouse"] + 1)
                         or LighthouseResult(status="ok")),
        raising=True,
    )

    def _rn(repo, env, *, qd_build, config=None, **k):
        spy["rn_bundle"] += 1
        assert qd_build is True  # the flag threads through
        return RnBundleResult(
            findings=[_qd_finding("metro", "rn_bundle_size_summary")], status="ok"
        )

    monkeypatch.setattr(quality_depth, "collect_rn_bundle", _rn, raising=True)

    result = run_quality_depth(
        tmp_path, base_env={}, stacks=["react-native"], qd_build=True
    )

    assert spy["axe"] == 0  # web gated off (no live_url)
    assert spy["lighthouse"] == 0
    assert spy["rn_bundle"] == 1
    assert result.status == "ok"


def test_returns_quality_depth_scan_result(tmp_path, monkeypatch):
    """The composite always returns a QualityDepthScanResult (the contract type)."""
    _patch_config(monkeypatch, live_url=None)
    result = run_quality_depth(tmp_path, base_env={}, stacks=[])
    assert isinstance(result, QualityDepthScanResult)


# --- Plan 15-05: prior carrier bytes threaded into the regression triggers ---


def _recording_collector(spy_key, spy):
    """Build a collect_* spy that records the kwargs it was called with."""

    def _collector(repo, env, **kwargs):
        spy[spy_key] = kwargs
        return AxeResult(status="ok")  # any QD result shape; we only read kwargs

    return _collector


def test_prior_web_bytes_threaded_into_lighthouse_step(tmp_path, monkeypatch):
    """run_quality_depth(prior_web_bytes=N) forwards prior_web_bytes=N to lighthouse."""
    _patch_config(monkeypatch, live_url="https://example.test")
    seen = {}

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        lambda *a, **k: AxeResult(status="ok"), raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        _recording_collector("lighthouse", seen), raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_rn_bundle",
        lambda *a, **k: RnBundleResult(status="ok"), raising=True,
    )

    run_quality_depth(
        tmp_path, base_env={}, stacks=["python"], prior_web_bytes=12345
    )

    assert seen["lighthouse"]["prior_web_bytes"] == 12345


def test_prior_rn_bytes_threaded_into_rn_bundle_step(tmp_path, monkeypatch):
    """run_quality_depth(prior_rn_bytes=M) forwards prior_rn_bytes=M to rn_bundle."""
    _patch_config(monkeypatch, live_url=None)
    seen = {}

    monkeypatch.setattr(
        quality_depth, "collect_rn_bundle",
        _recording_collector("rn_bundle", seen), raising=True,
    )

    run_quality_depth(
        tmp_path, base_env={}, stacks=["react-native"], qd_build=True,
        prior_rn_bytes=67890,
    )

    assert seen["rn_bundle"]["prior_rn_bytes"] == 67890
    # the existing qd_build kwarg still threads alongside the new prior bytes
    assert seen["rn_bundle"]["qd_build"] is True


def test_prior_bytes_default_to_none_when_omitted(tmp_path, monkeypatch):
    """Omitting the prior bytes → both forwarded as None (no fabricated baseline)."""
    _patch_config(monkeypatch, live_url="https://example.test")
    seen = {}

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        lambda *a, **k: AxeResult(status="ok"), raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        _recording_collector("lighthouse", seen), raising=True,
    )

    def _rn(repo, env, **kwargs):
        seen["rn_bundle"] = kwargs
        return RnBundleResult(status="ok")

    monkeypatch.setattr(quality_depth, "collect_rn_bundle", _rn, raising=True)

    # RN surface present so rn_bundle is invoked too.
    run_quality_depth(tmp_path, base_env={}, stacks=["expo"])

    assert seen["lighthouse"]["prior_web_bytes"] is None
    assert seen["rn_bundle"]["prior_rn_bytes"] is None


def test_axe_step_unchanged_by_prior_bytes(tmp_path, monkeypatch):
    """The axe step never gains a prior-bytes kwarg (a11y has no regression branch)."""
    _patch_config(monkeypatch, live_url="https://example.test")
    seen = {}

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        _recording_collector("axe", seen), raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        lambda *a, **k: LighthouseResult(status="ok"), raising=True,
    )

    run_quality_depth(
        tmp_path, base_env={}, stacks=["python"],
        prior_web_bytes=999, prior_rn_bytes=888,
    )

    assert "prior_web_bytes" not in seen["axe"]
    assert "prior_rn_bytes" not in seen["axe"]


def test_no_surface_gate_holds_even_with_prior_bytes(tmp_path, monkeypatch):
    """Prior bytes must NOT defeat the no-egress not_applicable gate."""
    _patch_config(monkeypatch, live_url=None)
    spy = {"axe": 0, "lighthouse": 0, "rn_bundle": 0}

    monkeypatch.setattr(
        quality_depth, "collect_axe",
        lambda *a, **k: (spy.__setitem__("axe", spy["axe"] + 1)
                         or AxeResult(status="ok")),
        raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_lighthouse",
        lambda *a, **k: (spy.__setitem__("lighthouse", spy["lighthouse"] + 1)
                         or LighthouseResult(status="ok")),
        raising=True,
    )
    monkeypatch.setattr(
        quality_depth, "collect_rn_bundle",
        lambda *a, **k: (spy.__setitem__("rn_bundle", spy["rn_bundle"] + 1)
                         or RnBundleResult(status="ok")),
        raising=True,
    )

    # No live_url AND no RN surface → not_applicable; prior bytes supplied anyway.
    result = run_quality_depth(
        tmp_path, base_env={}, stacks=["python"],
        prior_web_bytes=12345, prior_rn_bytes=67890,
    )

    assert result.status == "not_applicable"
    assert spy == {"axe": 0, "lighthouse": 0, "rn_bundle": 0}
