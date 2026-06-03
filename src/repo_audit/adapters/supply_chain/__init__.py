"""Cross-stack supply-chain adapter package (Phase 12).

Like ``adapters/sca`` this package is CROSS-STACK: its collectors run once per
repo regardless of the detected stack, NOT as per-stack ``@register_adapter``
entries.

Wave 1 (Plan 12-02) shipped:
    * :func:`history.collect_git_history` — HIST-01, the one-shot-per-repo
      full git-history secret collector.

Wave 1 (Plan 12-04) shipped:
    * :func:`sbom.generate_sbom` — SUP-02, the vendored-Syft CycloneDX SBOM
      generator (path-only carrier, written OUTSIDE the read-only target repo).

Wave 3 (Plan 12-05) ADDS :func:`run_supply_chain` — the cross-stack
``scan_runner`` STEP that composes ALL of Phase 12 into one never-raising
envelope, mirroring ``adapters/sast.run_sast`` / ``adapters/sca.run_sca``:

    SUP-02 generate_sbom          → sbom_path (referenced by path, D-12-07)
    SCA-04 collect_licenses(sbom) → offline copyleft/unknown-license findings
    SCA-04 collect_deprecated     → info-context (count + named list, D-12-08)
    SUP-01 promote_malicious      → promoted MAL (confirmed) + MAL-free CVE set
    HIST-01 collect_git_history   → net-new committed-then-deleted secrets

``run_supply_chain`` runs OUTSIDE the 95 s collector deadline (the full-history
walk + Syft each carry their own generous timeouts) and NEVER raises across its
boundary: every sub-step degradation folds into ``status`` + ``notes`` +
``ledger_notes`` so the scope ledger can disclose it honestly (SAFE-08).

The sub-collectors are imported into THIS module namespace (and called via the
module names) so tests can monkeypatch them on the package — the same patchable
indirection ``scan_runner`` uses for its cross-stack steps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal, Optional

# Sub-collectors imported into the package namespace so run_supply_chain can call
# them via the module-level names (monkeypatchable in tests).
from repo_audit.adapters.sca.deprecated import (
    DeprecatedResult,
    collect_deprecated,
)
from repo_audit.adapters.sca.licenses import collect_licenses
from repo_audit.adapters.sca.malicious import promote_malicious
from repo_audit.adapters.supply_chain.history import (
    HistoryResult,
    collect_git_history,
)
from repo_audit.adapters.supply_chain.sbom import generate_sbom
from repo_audit.schema.finding import Finding

# An overall status mirroring the cross-stack-step envelopes. ``not_applicable``
# is reserved for parity with the Phase-11 steps even though the supply-chain
# step is always applicable (every repo has supply-chain surface).
SupplyChainStatus = Literal["ok", "unavailable", "timeout", "not_applicable"]


@dataclass
class SupplyChainResult:
    """The never-raise envelope returned by :func:`run_supply_chain`.

    Mirrors ``adapters/sast.SastScanResult`` / ``adapters/sca.ScaScanResult``
    plus the fields this composite step needs:

        findings           -- the supply-chain findings merged into the security
                              dimension: history (net-new) + promoted MAL
                              (confidence='confirmed') + offline license risk.
        cve_findings       -- the MAL-FREE remainder of the SCA finding set,
                              handed back to the caller so the CVE partition is
                              never double-counted (T-12-05-DIL). The caller
                              substitutes this for ``sca_result.findings`` in the
                              aggregate merge.
        sbom_path          -- the REFERENCE path to the generated CycloneDX SBOM
                              (D-12-07: never the inlined document); None when
                              the SBOM step degraded.
        deprecated_context -- the SCA-04 info-context envelope (count + named
                              list); NOT fix-generating findings (D-12-08).
        status             -- overall step status; folds into the partial flag
                              (an APPLICABLE degradation flips partial).
        notes              -- a one-line roll-up note for the ledger fold.
        ledger_notes       -- per-sub-step disclosure notes (SAFE-08); the caller
                              ``"; "``-joins them into ``scope_ledger.notes`` under
                              the "Supply-chain" label (mirrors the RLS / Mobile /
                              Phase-11 ledger-fold pattern).
    """

    findings: list[Finding] = field(default_factory=list)
    cve_findings: list[Finding] = field(default_factory=list)
    sbom_path: Optional[Path] = None
    deprecated_context: DeprecatedResult = field(default_factory=DeprecatedResult)
    status: SupplyChainStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


def run_supply_chain(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    scan_date: date,
    working_tree_findings: list[Finding],
    sca_findings: list[Finding],
) -> SupplyChainResult:
    """Run the cross-stack supply-chain step: HIST-01 + SUP-01 + SUP-02 + SCA-04.

    Composes the whole Phase-12 pipeline behind one never-raising envelope,
    mirroring ``run_sast`` / ``run_sca``:

        1. SUP-02 — ``generate_sbom(repo, env, scan_date)`` → capture sbom_path.
        2. SCA-04 license — ``collect_licenses(sbom_path)`` (offline-from-SBOM;
           a None sbom_path degrades to unavailable inside collect_licenses).
        3. SCA-04 deprecated — ``collect_deprecated(repo, env)`` → info-context.
        4. SUP-01 — ``promote_malicious(sca_findings)`` → ``(mal, cve)``; ``mal``
           joins the findings, ``cve`` is returned to the caller MAL-free.
        5. HIST-01 — ``collect_git_history(repo, working_tree_findings)`` →
           net-new committed-then-deleted history secrets.

    Findings merge in a STABLE deterministic order — history + promoted MAL +
    license — so SC-5 bit-identical re-runs hold. Every sub-step's status/notes
    fold into ``ledger_notes``; the overall ``status`` is ``ok`` unless a
    genuinely-applicable step degraded (mirrors the run_sast notes-folding). This
    step runs OUTSIDE the 95 s collector deadline (Pitfall 3); the full-history
    walk + Syft each own a generous internal timeout. NEVER raises.

    Args:
        repo_path: the repo to scan (read-only; the SBOM lands OUTSIDE it).
        base_env: the base child env (typically a ``build_scan_env`` tempdir env).
        scan_date: stamps the derived SBOM filename.
        working_tree_findings: the COLL-03 working-tree secret findings the
            history dedup keys against (so a still-present secret is not
            re-counted as a net-new history finding).
        sca_findings: the SCA finding set (osv+grype corroborated, MAL-* inline);
            ``promote_malicious`` splits MAL out of it.

    Returns:
        A :class:`SupplyChainResult`; never raises. ``findings`` carries the
        merged supply-chain findings, ``cve_findings`` the MAL-free remainder,
        ``sbom_path`` the SBOM reference (None on degradation), and
        ``ledger_notes`` the per-step disclosures.
    """
    ledger_notes: list[str] = []

    # 1. SUP-02 — generate the SBOM (path only; D-12-07). Called via the module
    #    name so tests can monkeypatch supply_chain.generate_sbom.
    sbom_result = generate_sbom(repo_path, env=base_env, scan_date=scan_date)
    sbom_path = sbom_result.sbom_path if sbom_result.status == "ok" else None
    if sbom_result.status != "ok":
        ledger_notes.append(f"SBOM ({sbom_result.status}): {sbom_result.notes}")

    # 2. SCA-04 license — offline-from-SBOM. A None sbom_path degrades to
    #    unavailable inside collect_licenses (no network egress).
    license_result = collect_licenses(sbom_path)
    if license_result.status != "ok":
        ledger_notes.append(
            f"License ({license_result.status}): {license_result.notes}"
        )

    # 3. SCA-04 deprecated — info-context only (D-12-08); never fix-generating.
    deprecated_result = collect_deprecated(repo_path, env=base_env)
    if deprecated_result.status != "ok":
        ledger_notes.append(
            f"Deprecated ({deprecated_result.status}): {deprecated_result.notes}"
        )

    # 4. SUP-01 — promote MAL-* out of the SCA set. The promoted MAL findings
    #    join the merged set; the MAL-FREE remainder (cve) is returned to the
    #    caller so the CVE partition is never double-counted (T-12-05-DIL).
    mal, cve = promote_malicious(sca_findings)

    # 5. HIST-01 — net-new committed-then-deleted secrets, deduped vs the
    #    working tree. Called via the module name (monkeypatchable in tests).
    history_result = collect_git_history(
        repo_path, working_tree_findings, env=base_env
    )
    if history_result.status != "ok":
        ledger_notes.append(
            f"History ({history_result.status}): {history_result.notes}"
        )

    # Merge in a STABLE order: history + promoted MAL + license (SC-5 determinism).
    findings: list[Finding] = (
        list(history_result.findings)
        + list(mal)
        + list(license_result.findings)
    )

    # Overall status: ok unless a genuinely-applicable step degraded. The
    # SUP-01 promotion is a pure transform (never degrades); the SBOM / license /
    # deprecated / history steps degrade to unavailable/timeout honestly. If any
    # degraded, surface the most-severe-by-presence as the roll-up status so the
    # partial flag flips (mirrors the run_sast notes-folding).
    sub_statuses = [
        sbom_result.status,
        license_result.status,
        deprecated_result.status,
        history_result.status,
    ]
    if any(s == "timeout" for s in sub_statuses):
        status: SupplyChainStatus = "timeout"
    elif any(s != "ok" for s in sub_statuses):
        status = "unavailable"
    else:
        status = "ok"

    notes = (
        "; ".join(ledger_notes)
        if ledger_notes
        else (
            f"supply-chain ok: {len(findings)} finding(s), "
            f"sbom={'yes' if sbom_path else 'no'}, "
            f"deprecated={deprecated_result.count}"
        )
    )

    return SupplyChainResult(
        findings=findings,
        cve_findings=list(cve),
        sbom_path=sbom_path,
        deprecated_context=deprecated_result,
        status=status,
        notes=notes,
        ledger_notes=ledger_notes,
    )


__all__ = [
    "HistoryResult",
    "collect_git_history",
    "generate_sbom",
    "collect_licenses",
    "collect_deprecated",
    "promote_malicious",
    "SupplyChainResult",
    "SupplyChainStatus",
    "run_supply_chain",
]
