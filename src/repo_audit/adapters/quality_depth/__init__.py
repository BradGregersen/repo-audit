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

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.adapters.quality_depth.axe import (
    AxeResult,
    AxeStatus,
    collect_axe,
)
from repo_audit.adapters.quality_depth.config import read_quality_depth_config
from repo_audit.adapters.quality_depth.detect import has_rn_surface
from repo_audit.adapters.quality_depth.lighthouse import (
    LighthouseResult,
    LighthouseStatus,
    collect_lighthouse,
)
from repo_audit.adapters.quality_depth.rn_bundle import (
    RnBundleResult,
    RnBundleStatus,
    collect_rn_bundle,
)
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


def run_quality_depth(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    stacks: Iterable[str] | None = None,
    qd_build: bool = False,
    prior_web_bytes: int | None = None,
    prior_rn_bytes: int | None = None,
) -> QualityDepthScanResult:
    """Compose the a11y + perf collectors behind one never-raising envelope.

    Mirrors ``adapters/architecture/__init__.py::run_architecture``. Composes the
    Plan-02/03 collectors:

      * A11Y-01 ``collect_axe`` — applicable only when a ``live_url`` is configured
        (the web egress opt-in, D-15-03). No live_url → the collector self-gates to
        ``unavailable`` WITHOUT egress.
      * PERF-01 ``collect_lighthouse`` — same live_url gate as axe.
      * PERF-01 ``collect_rn_bundle`` — applicable when the repo has an RN surface
        (``has_rn_surface``). The existing-artifact measure path runs whenever an
        RN surface is present; the throwaway Metro BUILD path is additionally gated
        on ``qd_build`` (the collector enforces this internally).

    GATE (the first-class not_applicable degrade — disclosed but NON-partial-
    flipping, the D-13-05 nuance): when there is NEITHER a configured ``live_url``
    NOR an RN surface, the WHOLE step short-circuits to ``not_applicable`` WITHOUT
    invoking ANY tool (no resolve, no run_tool, ZERO egress — SAFE-08).

    Static a11y lint (jsx-a11y / react-native-a11y) is NOT a step here — it flows
    through the typescript eslint adapter (Plan 02), not this composite.

    Each sub-collector is read OFF this module (``quality_depth.collect_*``) so
    tests monkeypatch them on the package namespace. The composite NEVER raises: a
    sub-collector exception folds to an ``unavailable`` disclosure. Status roll-up
    mirrors ``run_architecture._roll_up_status`` (timeout dominates > applicable
    degrade = unavailable > any ok = ok > else not_applicable).

    Args:
        repo_path: the target repository root (read-only; each collector's output
            lands OUTSIDE it via the caller-supplied / collector tempdirs).
        base_env: the base child env (a ``build_scan_env`` tempdir env) passed to
            every sub-collector.
        stacks: the detector's stack tags. Drives the RN-surface gate. ``None`` →
            treated as no RN surface (the web gate alone decides applicability).
        qd_build: opt-in flag unlocking the throwaway Metro production bundle build
            (PATH B). Default ``False`` — a fleet sweep NEVER builds.
        prior_web_bytes: the prior scan's web transfer-size baseline (the
            lighthouse ``web_transfer_bytes`` carrier from the prior sidecar),
            forwarded to ``collect_lighthouse`` so the ``web_transfer_regression``
            trigger can fire. ``None`` (default — a baseline run, or a prior with
            an unavailable carrier) → NO regression Finding (never a fabricated
            zero baseline; None-not-0, SAFE-04/08).
        prior_rn_bytes: the prior scan's RN bundle-size baseline (the metro
            ``rn_bundle_bytes`` carrier from the prior sidecar), forwarded to
            ``collect_rn_bundle`` so the ``rn_bundle_regression`` trigger can fire.
            ``None`` (default) → NO regression Finding (same None-not-0 honesty
            contract).

    Returns:
        A :class:`QualityDepthScanResult`; never raises.
    """
    repo_path = Path(repo_path)
    stack_list = list(stacks) if stacks is not None else []

    config = read_quality_depth_config(repo_path)
    live_url = config.live_url
    rn_applicable = has_rn_surface(stack_list)

    # GATE — no web surface (no live_url) AND no RN surface is a first-class
    # not_applicable degrade. NEITHER axe/lighthouse NOR rn_bundle is invoked (no
    # tool resolved, ZERO egress). Disclosed via the ledger but NON-partial-
    # flipping (D-13-05). A configured live_url OR an RN surface falls through.
    if not live_url and not rn_applicable:
        return QualityDepthScanResult(
            status="not_applicable",
            notes=(
                "Quality-depth not applicable: no web surface (no live_url) "
                "and no RN surface"
            ),
        )

    # (label, callable, applicable, kwargs) in the STABLE finding-merge order:
    # axe (a11y), then lighthouse (web perf), then rn_bundle (size). Each callable
    # is read off THIS module so tests monkeypatch quality_depth.collect_*.
    steps: list[tuple[str, object, bool, dict]] = [
        ("axe", collect_axe, bool(live_url), {"live_url": live_url}),
        (
            "lighthouse",
            collect_lighthouse,
            bool(live_url),
            {
                "live_url": live_url,
                "config": config,
                "prior_web_bytes": prior_web_bytes,
            },
        ),
        (
            "rn_bundle",
            collect_rn_bundle,
            rn_applicable,
            {
                "qd_build": qd_build,
                "config": config,
                "prior_rn_bytes": prior_rn_bytes,
            },
        ),
    ]

    ledger_notes: list[str] = []
    findings: list[Finding] = []
    statuses: list[tuple[str, bool]] = []

    for label, collector, applicable, kwargs in steps:
        if not applicable:
            # A non-applicable sub-step (no live_url for axe/lighthouse, no RN
            # surface for rn_bundle) is skipped WITHOUT invoking the tool — a
            # disclosed-but-non-partial-flipping not_applicable sub-status.
            statuses.append(("not_applicable", False))
            continue
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
        notes = f"Quality-depth ok: {len(findings)} finding(s)"
    else:
        notes = (
            "Quality-depth not applicable: no web surface (no live_url) "
            "and no RN surface"
        )

    return QualityDepthScanResult(
        findings=findings,
        status=status,
        notes=notes,
        ledger_notes=ledger_notes,
    )


def _roll_up_status(statuses: list[tuple[str, bool]]) -> QualityDepthStatus:
    """Roll the per-sub-step (status, applicable) pairs into the composite status.

    Copied verbatim from ``adapters/architecture/__init__.py::_roll_up_status``
    with the QualityDepthStatus return type:

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

    if any(applicable for _s, applicable in non_ok):
        return "unavailable"

    if any(s == "ok" for s, _ in statuses):
        return "ok"
    return "not_applicable"


__all__ = [
    "AxeResult",
    "AxeStatus",
    "LighthouseResult",
    "LighthouseStatus",
    "QualityDepthScanResult",
    "QualityDepthStatus",
    "RnBundleResult",
    "RnBundleStatus",
    "collect_axe",
    "collect_lighthouse",
    "collect_rn_bundle",
    "run_quality_depth",
]
