"""CI/CD & IaC security adapter package (Phase 13).

A CROSS-STACK adapter (like ``adapters/sast`` / ``adapters/sca`` /
``adapters/supply_chain``): it has no per-stack ``@register_adapter`` entry and
is wired into the pipeline as a dedicated repo-wide ``run_cicd`` step by
``orchestration/scan_runner`` — NOT through the stack-detection registry.

This Wave-0 skeleton ships ONLY the foundation both Wave-1 plans depend on:

  * :mod:`repo_audit.adapters.cicd.detect` — read-only detection-and-degrade
    globs (workflows / Dockerfiles / IaC config), driving the SAFE-08 honest
    ``unavailable`` path (D-13-05).
  * ``adapter.yaml`` — the 4-tool (zizmor / actionlint / hadolint / checkov)
    per-tool ``default_dimension`` + ``severity_map`` + ``timeout_ms`` descriptor,
    loaded under ``ruamel.yaml.YAML(typ='safe')`` (T-03-01).

``run_cicd`` + ``CicdScanResult`` (the never-raising composite envelope, Plan 04)
compose the four collectors behind ONE envelope, mirroring
``adapters/supply_chain/__init__.py::run_supply_chain``: each sub-collector is
called via its module-level (monkeypatchable) name, degradations fold into
``status`` + ``notes`` + ``ledger_notes`` (SAFE-08), findings merge in a stable
deterministic order, and the composite NEVER raises across its boundary.

The CRITICAL nuance is the D-13-05 first-class degrade (mirrors
``scan_runner._phase11_step_degraded``): a repo with NO CI/CD files degrades to
``not_applicable`` (disclosed but NON-partial-flipping) whereas an APPLICABLE
degradation — a tool absent while its files ARE present, or a timeout — rolls up
to ``unavailable`` / ``timeout`` (which DOES flip the scan to partial when
``scan_runner`` wires this step in).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.adapters.cicd import detect
from repo_audit.adapters.cicd.containers import collect_hadolint
from repo_audit.adapters.cicd.iac import collect_checkov
from repo_audit.adapters.cicd.workflows import (
    collect_actionlint,
    collect_zizmor,
)
from repo_audit.schema.finding import Finding

# Mirrors SupplyChainStatus: ``not_applicable`` is the no-CI/CD-files disposition
# (disclosed but NON-partial-flipping per _phase11_step_degraded); ``unavailable``
# / ``timeout`` are APPLICABLE degradations (flip partial in scan_runner).
CicdStatus = Literal["ok", "unavailable", "timeout", "not_applicable"]


@dataclass
class CicdScanResult:
    """The never-raise envelope returned by :func:`run_cicd`.

    Mirrors ``adapters/supply_chain.SupplyChainResult``:

        findings      -- the CI/CD findings merged in the STABLE deterministic
                         order zizmor (security) + actionlint (process) +
                         hadolint (security) + checkov (security).
        status        -- overall step status; ``ok`` when every applicable
                         sub-step succeeded, ``not_applicable`` when EVERY
                         sub-step degraded purely because its files were absent
                         (the D-13-05 first-class degrade — disclosed but does NOT
                         flip partial), ``timeout`` when any sub-step timed out,
                         else ``unavailable`` (an applicable degradation flips
                         partial in scan_runner).
        notes         -- a one-line roll-up note for the ledger fold.
        ledger_notes  -- per-sub-step disclosure notes (SAFE-08); the caller
                         ``"; "``-joins them into ``scope_ledger.notes`` under the
                         "CI/CD" label (mirrors the Supply-chain ledger fold).
    """

    findings: list[Finding] = field(default_factory=list)
    status: CicdStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


# The four sub-collectors, paired with the detect predicate that says whether
# their surface is present (so a no-files "unavailable" can be distinguished from
# a tool-absent "unavailable" at the composite level — the D-13-05 nuance). The
# order is the STABLE finding-merge order (zizmor, actionlint, hadolint, checkov).
def _surface_present(repo_path: Path) -> dict[str, bool]:
    """Resolve which CI/CD surfaces are present (read-only, call-time)."""
    surface = detect.detect_cicd_surface(repo_path)
    return {
        "zizmor": surface.has_workflows,
        "actionlint": surface.has_workflows,
        "hadolint": surface.has_dockerfiles,
        "checkov": surface.has_iac_config,
    }


def run_cicd(repo_path: Path, *, base_env: dict[str, str]) -> CicdScanResult:
    """Compose the four CI/CD collectors behind one never-raising envelope.

    Calls each sub-collector via its module-level (monkeypatchable) name in the
    fixed order zizmor → actionlint → hadolint → checkov, each passing
    ``base_env``. Every degrading sub-step appends a human-readable
    ``ledger_note``; findings merge in that same fixed order (re-run
    deterministic). The composite NEVER raises: an unexpected sub-collector
    exception is caught and folds to an ``unavailable`` disclosure.

    Status roll-up (mirrors ``run_supply_chain`` + the ``_phase11_step_degraded``
    not-applicable nuance):

      * any sub-step ``timeout`` → ``timeout``;
      * else if ANY APPLICABLE sub-step degraded (a tool absent while its files
        ARE present, a parse failure, or a caught exception) → ``unavailable``;
      * else if at least one sub-step scanned ``ok`` → ``ok`` (any remaining
        non-ok steps are pure no-files degrades — e.g. workflows present and
        scanned while no Dockerfile/IaC exist — disclosed via ledger notes);
      * else (EVERY sub-step degraded purely because its surface was absent —
        no workflows / no Dockerfile / no IaC at all) → ``not_applicable``
        (disclosed but NON-partial-flipping — D-13-05).

    Args:
        repo_path: the target repository root (read-only; checkov's SARIF lands
            OUTSIDE it — the caller supplies a tempdir-backed ``base_env``).
        base_env: the base child env (typically a ``build_scan_env`` tempdir env)
            passed to every sub-collector.

    Returns:
        A :class:`CicdScanResult`; never raises.
    """
    repo_path = Path(repo_path)
    present = _surface_present(repo_path)

    # (label, callable) in the STABLE finding-merge order. Each callable is read
    # off THIS module so tests can monkeypatch cicd.collect_zizmor etc.
    steps: list[tuple[str, object]] = [
        ("zizmor", collect_zizmor),
        ("actionlint", collect_actionlint),
        ("hadolint", collect_hadolint),
        ("checkov", collect_checkov),
    ]

    ledger_notes: list[str] = []
    findings: list[Finding] = []
    # Per-step status, paired with whether that step's surface was applicable, so
    # the roll-up can tell a no-files degrade from an applicable degrade.
    statuses: list[tuple[str, bool]] = []

    for label, collector in steps:
        applicable = present.get(label, True)
        try:
            sub = collector(repo_path, base_env)  # type: ignore[operator]
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
        notes = f"CI/CD ok: {len(findings)} finding(s)"
    else:
        notes = "CI/CD not applicable: no .github/workflows, Dockerfile, or IaC config"

    return CicdScanResult(
        findings=findings,
        status=status,
        notes=notes,
        ledger_notes=ledger_notes,
    )


def _roll_up_status(statuses: list[tuple[str, bool]]) -> CicdStatus:
    """Roll the per-sub-step (status, applicable) pairs into the composite status.

    * any ``timeout`` dominates → ``timeout``;
    * else if any APPLICABLE step degraded → ``unavailable``;
    * else if at least one step scanned ``ok`` → ``ok`` (any remaining non-ok
      steps are pure no-files degrades, disclosed via ledger notes);
    * else (EVERY step is a no-files degrade, i.e. no CI/CD surface at all) →
      ``not_applicable`` (D-13-05 NON-partial-flipping).
    """
    if any(s == "timeout" for s, _ in statuses):
        return "timeout"

    non_ok = [(s, applicable) for s, applicable in statuses if s != "ok"]
    if not non_ok:
        return "ok"

    # An applicable degradation = a non-ok step whose surface WAS present.
    if any(applicable for _s, applicable in non_ok):
        return "unavailable"

    # Every non-ok step degraded purely because its files were absent. If at
    # least one OTHER surface was scanned ``ok`` (e.g. workflows present and
    # scanned, but no Dockerfile/IaC), the composite IS applicable and succeeded
    # → ``ok`` (the absent surfaces are disclosed in ledger notes, NOT promoted
    # to a whole-composite not-applicable). Only when ZERO steps scanned ``ok``
    # — no CI/CD surface present at all — is the composite ``not_applicable``.
    if any(s == "ok" for s, _ in statuses):
        return "ok"
    return "not_applicable"


__all__ = [
    "CicdScanResult",
    "CicdStatus",
    "collect_actionlint",
    "collect_checkov",
    "collect_hadolint",
    "collect_zizmor",
    "run_cicd",
]
