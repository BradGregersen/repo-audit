"""Quality-depth (accessibility + performance) adapter package (Phase 15).

A CROSS-STACK adapter (like ``adapters/architecture`` / ``adapters/cicd`` /
``adapters/sast`` / ``adapters/sca`` / ``adapters/supply_chain``): it has NO
per-stack ``@register_adapter`` entry and is wired into the pipeline as a
dedicated repo-wide ``run_quality_depth`` step by ``orchestration/scan_runner``
in Plan 04 — NOT through the stack-detection registry. Like ``run_architecture``
it runs OUTSIDE the 95s collector deadline: a live-URL axe/Lighthouse pass and a
``react-native bundle`` build can each take minutes, so the step owns its own
generous per-tool ``timeout_ms`` (see ``adapter.yaml`` — ``rn_bundle`` carries
the MOB-03 900s override).

This Wave-0 plan (15-01) ships ONLY the SKELETON — the contract names every later
wave's ``importorskip``/``skipif`` gate resolves against:

  * :class:`QualityDepthScanResult` — the never-raising composite envelope
    (mirrors ``adapters/architecture.ArchitectureScanResult``) with exactly four
    fields. The skeleton lets ``skipif(not hasattr(..., "run_quality_depth"))``
    flip ACTIVE the instant Plan 04 lands the composite.
  * ``quality_depth.detect.has_rn_surface`` — the RN-bundle applicability gate.
  * ``adapter.yaml`` — the 3-tool (axe / lighthouse / rn_bundle) per-tool
    ``default_dimension`` (all ``quality_debt`` at the block level; the maps
    construct the PUBLIC ``quality`` per-Finding dimension — PATTERNS §Dimension
    token) + ``severity_map`` + ``timeout_ms`` (+ a ``budgets`` block)
    descriptor, loaded under ``ruamel.yaml.YAML(typ='safe')`` (T-15-01).

What is DELIBERATELY NOT here yet (so the Wave-1/2 ``importorskip`` test gates
stay SKIPPED, never ERROR):

  * ``quality_depth.config`` — SHIPPED in this plan (Task 2) for the call-time
    ``.repo-audit.yaml`` reader; the COLLECTORS that consume it land later:
  * ``quality_depth.axe_json`` + ``quality_depth.collect_axe`` (Plan 02 —
    A11Y-01 axe-core runtime tier, live-URL gated)
  * ``quality_depth.lighthouse_json`` + ``quality_depth.collect_lighthouse``
    (Plan 03 — PERF-01 web aggregate, live-URL gated)
  * ``quality_depth.rn_bundle`` + ``quality_depth.collect_rn_bundle`` (Plan 03 —
    PERF-01 RN bundle size, RN-surface + qd_build gated)
  * ``run_quality_depth`` (Plan 04 — the composite roll-up). ``hasattr(...,
    "run_quality_depth")`` is intentionally False until then.

``run_quality_depth`` (Plan 04) will compose the sub-collectors behind one
never-raising envelope, mirroring ``adapters/architecture/__init__.py::
run_architecture``: a non-applicable surface (no ``live_url`` AND no RN surface)
short-circuits to ``not_applicable`` WITHOUT invoking any tool (the first-class
degrade — disclosed but NON-partial-flipping); an applicable degradation (a URL
configured but axe absent, an RN stack present but the bundle build failing)
folds to ``unavailable`` and DOES flip partial. Only ``QualityDepthScanResult``
and ``QualityDepthStatus`` are exported here in Wave 0.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from repo_audit.schema.finding import Finding

# Mirrors ArchitectureStatus / CicdStatus: ``not_applicable`` is the
# no-web-surface (no live_url) AND no-RN-surface disposition — disclosed but
# NON-partial-flipping; ``unavailable`` / ``timeout`` are APPLICABLE
# degradations (a live_url configured but axe/lighthouse absent, or an RN stack
# present but the bundle build failing/timing out) that DO flip the scan to
# partial when scan_runner wires this step in (Plan 04).
QualityDepthStatus = Literal["ok", "unavailable", "timeout", "not_applicable"]


@dataclass
class QualityDepthScanResult:
    """The never-raise envelope returned by ``run_quality_depth`` (Plan 04).

    Mirrors ``adapters/architecture.ArchitectureScanResult`` field-for-field:

        findings      -- the quality-depth findings merged in the STABLE
                         deterministic order (axe a11y, then lighthouse web perf,
                         then rn_bundle size).
        status        -- overall step status; ``ok`` when every applicable
                         sub-step succeeded, ``not_applicable`` when the repo has
                         neither a configured ``live_url`` nor an RN surface (the
                         first-class degrade — disclosed but does NOT flip
                         partial), ``timeout`` when any sub-step timed out, else
                         ``unavailable`` (an applicable degradation flips partial
                         in scan_runner).
        notes         -- a one-line roll-up note for the ledger fold.
        ledger_notes  -- per-sub-step disclosure notes (SAFE-08); the caller
                         ``"; "``-joins them into ``scope_ledger.notes`` under the
                         "Quality Depth" label.

    Plan 04 lands ``run_quality_depth`` (which constructs and returns this) and
    the sub-collectors. This Wave-0 skeleton ships ONLY the envelope so the
    contract name resolves.
    """

    findings: list[Finding] = field(default_factory=list)
    status: QualityDepthStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


__all__ = [
    "QualityDepthScanResult",
    "QualityDepthStatus",
]
