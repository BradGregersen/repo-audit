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

``run_architecture`` (Plan 04) composes the two sub-collectors behind one
never-raising envelope, mirroring ``adapters/cicd/__init__.py::run_cicd`` reduced
from four steps to two:

  * ARCH-01 ``collect_dependency_cruiser`` — applicable only on a JS/TS dependency
    graph (``has_js_dependency_graph(stacks)``); a non-JS stack makes the WHOLE
    architecture step ``not_applicable`` WITHOUT invoking either tool (the
    first-class degrade — disclosed but NON-partial-flipping, D-13-05 nuance).
  * ARCH-02 ``collect_jscpd`` — always applicable (repo-wide, language-agnostic,
    D-14-01).

The collectors are read OFF this module (``architecture.collect_dependency_cruiser``
/ ``architecture.collect_jscpd``) so tests can monkeypatch them on the package
namespace; the composite NEVER raises across its boundary (a sub-collector
exception folds to an ``unavailable`` disclosure).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.adapters.architecture.circular import (
    collect_dependency_cruiser,
)
from repo_audit.adapters.architecture.detect import has_js_dependency_graph
from repo_audit.adapters.architecture.duplication import collect_jscpd
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


def run_architecture(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    stacks: Iterable[str] | None = None,
) -> ArchitectureScanResult:
    """Compose the two architecture collectors behind one never-raising envelope.

    Mirrors ``adapters/cicd/__init__.py::run_cicd`` reduced from four steps to two.
    The ARCH-01 step (dependency-cruiser) is applicable only when ``stacks`` carry
    a JS/TS dependency graph (``has_js_dependency_graph``); the ARCH-02 step (jscpd)
    is always applicable (repo-wide, language-agnostic). When NO JS dependency
    graph is present the WHOLE step short-circuits to ``not_applicable`` WITHOUT
    invoking either tool (the first-class degrade — disclosed but NON-partial-
    flipping, the D-13-05 nuance).

    Each sub-collector is read off THIS module (``architecture.collect_*``) so tests
    monkeypatch them on the package namespace. Findings merge in the STABLE order
    circular (dependency-cruiser) then duplication (jscpd). The composite NEVER
    raises: an unexpected sub-collector exception is caught and folds to an
    ``unavailable`` disclosure.

    Status roll-up (mirrors ``run_cicd._roll_up_status``):

      * any sub-step ``timeout`` → ``timeout`` (dominates);
      * else if any APPLICABLE sub-step degraded (a JS stack present but a tool
        absent / a parse failure / a caught exception) → ``unavailable``;
      * else if at least one sub-step scanned ``ok`` → ``ok``;
      * else → ``not_applicable``.

    Args:
        repo_path: the target repository root (read-only; each collector's report
            lands OUTSIDE it via the caller-supplied tempdir ``base_env``).
        base_env: the base child env (typically a ``build_scan_env`` tempdir env)
            passed to every sub-collector.
        stacks: the detector's stack tags (``detection.stacks`` tags). Drives the
            ARCH-01 applicability gate; ``None`` falls through to the collector's
            own ``package.json`` filesystem fallback (the standalone path).

    Returns:
        An :class:`ArchitectureScanResult`; never raises.
    """
    repo_path = Path(repo_path)

    # GATE — no JS dependency graph is a first-class not-applicable degrade. When
    # ``stacks`` is supplied and carries no JS/TS stack, NEITHER tool is invoked
    # (RESEARCH Discretion #5 / the D-13-05 nuance): dependency-cruiser AND jscpd
    # are both skipped, the whole architecture step degrades to not_applicable
    # (disclosed via the ledger but NON-partial-flipping). ``stacks=None`` is the
    # standalone path — fall through and let each collector self-gate.
    js_applicable = stacks is None or has_js_dependency_graph(stacks)
    if not js_applicable:
        return ArchitectureScanResult(
            status="not_applicable",
            notes="Architecture not applicable: no JS/TS dependency graph stack",
        )

    # (label, callable, applicable) in the STABLE finding-merge order. Each callable
    # is read off THIS module so tests can monkeypatch
    # architecture.collect_dependency_cruiser / architecture.collect_jscpd.
    steps: list[tuple[str, object, bool, dict]] = [
        # dependency-cruiser carries the JS gate (always True here — the whole
        # step already short-circuited above on a non-JS stack); pass ``stacks``
        # through so the collector's own GATE 1 matches the composite decision.
        ("dependency-cruiser", collect_dependency_cruiser, True, {"stacks": stacks}),
        ("jscpd", collect_jscpd, True, {}),
    ]

    ledger_notes: list[str] = []
    findings: list[Finding] = []
    statuses: list[tuple[str, bool]] = []

    for label, collector, applicable, kwargs in steps:
        try:
            sub = collector(repo_path, base_env, **kwargs)  # type: ignore[operator]
            sub_status = getattr(sub, "status", "unavailable")
            sub_findings = list(getattr(sub, "findings", []) or [])
            sub_notes = getattr(sub, "notes", "")
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            # A crashed sub-step is an APPLICABLE degradation (we tried to run it).
            sub_status = "unavailable"
            sub_findings = []
            sub_notes = f"{type(exc).__name__}: {exc}"
            applicable = True

        findings.extend(sub_findings)
        statuses.append((sub_status, applicable))
        if sub_status != "ok":
            ledger_notes.append(f"{label} ({sub_status}): {sub_notes}")

    status = _roll_up_status(statuses)

    if ledger_notes:
        notes = "; ".join(ledger_notes)
    elif status == "ok":
        notes = f"Architecture ok: {len(findings)} finding(s)"
    else:
        notes = "Architecture not applicable: no JS/TS dependency graph stack"

    return ArchitectureScanResult(
        findings=findings,
        status=status,
        notes=notes,
        ledger_notes=ledger_notes,
    )


def _roll_up_status(statuses: list[tuple[str, bool]]) -> ArchitectureStatus:
    """Roll the per-sub-step (status, applicable) pairs into the composite status.

    Copied from ``adapters/cicd/__init__.py::_roll_up_status`` with the
    ArchitectureStatus return type:

    * any ``timeout`` dominates → ``timeout``;
    * else if any APPLICABLE step degraded → ``unavailable``;
    * else if at least one step scanned ``ok`` → ``ok`` (any remaining non-ok steps
      are pure not-applicable degrades, disclosed via ledger notes);
    * else (EVERY step is a non-applicable degrade) → ``not_applicable``.
    """
    if any(s == "timeout" for s, _ in statuses):
        return "timeout"

    non_ok = [(s, applicable) for s, applicable in statuses if s != "ok"]
    if not non_ok:
        return "ok"

    # An applicable degradation = a non-ok step whose surface WAS applicable.
    if any(applicable for _s, applicable in non_ok):
        return "unavailable"

    if any(s == "ok" for s, _ in statuses):
        return "ok"
    return "not_applicable"


__all__ = [
    "ArchitectureScanResult",
    "ArchitectureStatus",
    "collect_dependency_cruiser",
    "collect_jscpd",
    "run_architecture",
]
