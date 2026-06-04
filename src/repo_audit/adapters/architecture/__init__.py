"""Architecture-fitness & duplication adapter package (Phase 14).

A CROSS-STACK adapter (like ``adapters/cicd`` / ``adapters/sast`` /
``adapters/sca`` / ``adapters/supply_chain``): it has no per-stack
``@register_adapter`` entry and is wired into the pipeline as a dedicated
repo-wide ``run_architecture`` step by ``orchestration/scan_runner`` — NOT
through the stack-detection registry. Like ``run_cicd`` / ``run_sast`` it runs
OUTSIDE the 95s collector deadline (RESEARCH Open Q2): depcruise + jscpd over a
large monorepo can exceed it, so the step owns its own generous per-tool
``timeout_ms`` (see ``adapter.yaml``).

This Wave-0 plan (14-01) ships ONLY the SKELETON — the contract names every
later wave's ``importorskip`` target resolves against:

  * :class:`ArchitectureScanResult` — the never-raising composite envelope
    (mirrors ``adapters/cicd.CicdScanResult`` / ``supply_chain.SupplyChainResult``)
    with exactly four fields. The skeleton lets ``skipif(not hasattr(...,
    "run_architecture"))`` flip ACTIVE the instant Plan 04 lands the composite.
  * ``adapter.yaml`` — the 2-tool (depcruise / jscpd) per-tool
    ``default_dimension`` (both ``architecture_rot``) + ``severity_map`` +
    ``timeout_ms`` (+ jscpd thresholds) descriptor, loaded under
    ``ruamel.yaml.YAML(typ='safe')`` (T-03-01).

What is DELIBERATELY NOT here yet (so the Wave-1/2/3 ``importorskip`` test gates
stay SKIPPED, never ERROR):

  * ``architecture.detect`` (Plan 02/03 — ``has_js_dependency_graph`` predicate)
  * ``architecture.circular`` + ``architecture.depcruise_json`` (Plan 02 —
    ARCH-01 dependency-cruiser collector + JSON→Finding map)
  * ``architecture.duplication`` + ``architecture.jscpd_json`` (Plan 03 —
    ARCH-02 jscpd collector + JSON→Finding map)
  * ``run_architecture`` (Plan 04 — the composite roll-up). ``hasattr(...,
    "run_architecture")`` is intentionally False until then.

Importing this package therefore has NO side effects beyond defining the
dataclass + Literal — no submodules, no registry mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from repo_audit.schema.finding import Finding

# Mirrors CicdStatus / SupplyChainStatus: ``not_applicable`` is the
# no-JS-dependency-graph (non-JS stack) disposition — disclosed but
# NON-partial-flipping; ``unavailable`` / ``timeout`` are APPLICABLE
# degradations (a JS stack present but depcruise/jscpd absent or timed out) that
# DO flip the scan to partial when scan_runner wires this step in (Plan 04).
ArchitectureStatus = Literal["ok", "unavailable", "timeout", "not_applicable"]


@dataclass
class ArchitectureScanResult:
    """The never-raise envelope returned by ``run_architecture`` (Plan 04).

    Mirrors ``adapters/cicd.CicdScanResult`` field-for-field:

        findings      -- the architecture findings merged in the STABLE
                         deterministic order: circular (depcruise) then
                         duplication (jscpd).
        status        -- overall step status; ``ok`` when every applicable
                         sub-step succeeded, ``not_applicable`` when the repo has
                         no JS dependency-graph stack at all (the first-class
                         degrade — disclosed but does NOT flip partial),
                         ``timeout`` when any sub-step timed out, else
                         ``unavailable`` (an applicable degradation flips partial
                         in scan_runner).
        notes         -- a one-line roll-up note for the ledger fold.
        ledger_notes  -- per-sub-step disclosure notes (SAFE-08); the caller
                         ``"; "``-joins them into ``scope_ledger.notes`` under the
                         "Architecture" label.

    Plan 04 lands ``run_architecture`` (which constructs and returns this) and
    the two sub-collectors. This Wave-0 skeleton ships ONLY the envelope so the
    contract name resolves.
    """

    findings: list[Finding] = field(default_factory=list)
    status: ArchitectureStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


__all__ = [
    "ArchitectureScanResult",
    "ArchitectureStatus",
]
