"""Wave-0 skeleton contract for the quality_depth adapter (Plan 15-01, Task 1).

These tests are ACTIVE from the moment the package skeleton lands — they pin the
contract names every later wave's ``importorskip``/``skipif`` gate resolves
against:

  * :class:`QualityDepthScanResult` — the never-raising composite envelope
    (mirrors ``adapters/architecture.ArchitectureScanResult``) with exactly four
    fields. ``run_quality_depth`` (the composite) is DELIBERATELY absent — Plan
    04 owns it; a ``skipif(not hasattr(..., "run_quality_depth"))`` flips ACTIVE
    the instant it lands.
  * ``quality_depth.detect.has_rn_surface`` — the RN-bundle applicability gate.
  * ``adapter.yaml`` — the 3-tool (axe / lighthouse / rn_bundle) descriptor with
    the documented ``budgets`` defaults, loaded under
    ``ruamel.yaml.YAML(typ='safe')`` (T-15-01).
"""
from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML

import repo_audit.adapters.quality_depth as qd_pkg
from repo_audit.adapters.quality_depth import (
    QualityDepthScanResult,
    QualityDepthStatus,
)
from repo_audit.adapters.quality_depth import detect as qd_detect

_ADAPTER_YAML = (
    Path(repo_audit_file := qd_pkg.__file__).parent / "adapter.yaml"
)


def test_result_imports_and_defaults_to_ok() -> None:
    """The contract imports and a bare result defaults to status='ok'."""
    result = QualityDepthScanResult()
    assert result.status == "ok"


def test_result_has_exactly_the_four_fields() -> None:
    """Fields are exactly {findings, status, notes, ledger_notes} (cicd analog)."""
    result = QualityDepthScanResult()
    assert set(result.__dataclass_fields__) == {
        "findings",
        "status",
        "notes",
        "ledger_notes",
    }
    assert result.findings == []
    assert result.notes == ""
    assert result.ledger_notes == []


def test_status_literal_members() -> None:
    """QualityDepthStatus is the 4-member literal mirroring ArchitectureStatus."""
    import typing

    assert set(typing.get_args(QualityDepthStatus)) == {
        "ok",
        "unavailable",
        "timeout",
        "not_applicable",
    }


def test_run_quality_depth_absent_until_plan_04() -> None:
    """The composite is DELIBERATELY not shipped in Wave 0 (Plan 04 owns it)."""
    assert not hasattr(qd_pkg, "run_quality_depth")


def test_has_rn_surface_gate() -> None:
    """RN-bundle gate: react-native / expo → True; everything else → False."""
    assert qd_detect.has_rn_surface(["react-native"]) is True
    assert qd_detect.has_rn_surface(["expo"]) is True
    assert qd_detect.has_rn_surface(["expo", "kotlin-android"]) is True
    assert qd_detect.has_rn_surface(["python"]) is False
    assert qd_detect.has_rn_surface(["typescript-node"]) is False
    assert qd_detect.has_rn_surface([]) is False


def test_no_has_web_surface_predicate() -> None:
    """Web applicability is gated by live_url in config, NOT a stack predicate."""
    assert not hasattr(qd_detect, "has_web_surface")


def test_adapter_yaml_parses_under_safe_loader() -> None:
    """adapter.yaml loads under YAML(typ='safe') with the 3 per-tool blocks."""
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML.open(encoding="utf-8") as fh:
        cfg = yaml.load(fh)
    tools = cfg["tools"]
    assert {"axe", "lighthouse", "rn_bundle"} <= set(tools)
    for tool in ("axe", "lighthouse", "rn_bundle"):
        assert tools[tool]["default_dimension"] == "quality_debt"


def test_adapter_yaml_budgets_defaults() -> None:
    """The budgets block carries the five documented defaults."""
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML.open(encoding="utf-8") as fh:
        cfg = yaml.load(fh)
    budgets = cfg["budgets"]
    assert budgets["web_budget_bytes"] == 256000
    assert budgets["rn_budget_bytes"] == 512000
    assert budgets["regression_pct"] == 10
    assert budgets["regression_floor_bytes"] == 10240
    assert budgets["rn_entry_file"] == "index.js"


def test_rn_bundle_has_long_timeout() -> None:
    """rn_bundle carries the MOB-03 900s override; lighthouse/axe are generous."""
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML.open(encoding="utf-8") as fh:
        cfg = yaml.load(fh)
    tools = cfg["tools"]
    assert tools["rn_bundle"]["timeout_ms"] == 900000
    assert tools["lighthouse"]["timeout_ms"] == 120000
    assert tools["axe"]["timeout_ms"] == 120000
