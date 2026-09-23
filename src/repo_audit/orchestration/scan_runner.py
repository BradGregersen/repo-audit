"""Single-source-of-truth scan pipeline (RESEARCH Pattern 2).

`run_scan()` runs the ENTIRE single-repo pipeline that `cli.py::scan` used to
inline. Both ``repo-audit scan`` (cli.py) and ``repo-audit fleet`` (Plan 05) call this so
the pipeline is implemented exactly once — fleet must NOT re-implement the
pipeline nor call the Typer command directly (fragile: option defaults,
``typer.Exit``, stderr echoes).

The function returns a ``ScanResult`` (a plain data carrier) instead of calling
``typer.Exit`` / ``typer.echo``; the caller decides how to surface exit codes,
the integrity alert, the agent-status line, and the "Wrote ..." messages. This
keeps the pipeline free of CLI-presentation concerns while preserving every
documented invariant verbatim (D-33, D-65, D-67).

Read-only contract (REP-03 / Pitfall 7): the only legitimate write is the
sidecar pair under ``docs/state-reports/`` (via ``render_and_write``). The
post-flight ``diff_git_status`` integrity tripwire stays in ``run_scan`` and
must remain — it catches collector/tool BUGS that touch the target repo.

baseline_run (D-12, RESEARCH Pitfall 4): no longer hard-coded ``True``. It is
``True`` only when ``find_prior_sidecar`` finds no usable prior JSON sidecar
dated strictly before today; otherwise ``False`` (the first real trend scan
flips it off).
"""
from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from datetime import date as _date
from pathlib import Path

from repo_audit import __version__
from repo_audit.adapters import run_adapters
from repo_audit.adapters.architecture import run_architecture
from repo_audit.adapters.byo.commercial import (
    COMMERCIAL_TOOLS,
    run_byo_commercial,
)
from repo_audit.adapters.byo.config import load_byo_config
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.cicd import run_cicd
from repo_audit.adapters.codeql import run_codeql
from repo_audit.adapters.codeql.config import load_codeql_config
from repo_audit.adapters.dast import run_dast
from repo_audit.adapters.dast.config import read_dast_config
from repo_audit.adapters.e2e import run_e2e
from repo_audit.adapters.fuzz import run_fuzz
from repo_audit.adapters.mobile import run_mobile
from repo_audit.adapters.quality_depth import run_quality_depth
from repo_audit.adapters.sast import run_sast
from repo_audit.adapters.sca import run_sca
from repo_audit.adapters.supabase import run_supabase
from repo_audit.adapters.supply_chain import run_supply_chain
from repo_audit.adapters.test_depth import run_expo, run_kotlin, run_test_depth
from repo_audit.adapters.typescript.refresh import _NODE_STACKS
from repo_audit.collectors import run_collectors
from repo_audit.detect.detector import detect_stacks
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.meta.paths import find_prior_sidecar, state_report_paths
from repo_audit.meta.slug import repo_slug
from repo_audit.orchestration.scope_ledger_builder import (
    auto_fill_ledger_gaps,
    build_scope_ledger,
)
from repo_audit.render.renderer import render_and_write
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.trend.delta import (
    _rn_bundle_metric,
    _web_transfer_metric,
    compute_trend,
)
from repo_audit.walker import build_repo_index


# SCAN-BOUND-01 (D-051-06) — per-scan wall-clock budget threaded into
# run_collectors as a deadline.
#
# 05.1-gap: lowered from 300 s and now ENFORCED INSIDE the read-heavy /
# subprocess collectors, not only between them. The Blocker-A bottleneck was
# secret_detection spawning a gitleaks subprocess PER text file: on a very large
# monorepo (thousands of text files) that never finished inside the 120 s acceptance
# canary. The between-collector check (the prior mechanism) could not interrupt
# it once running. Each read-heavy collector now polls THIS deadline from inside
# its own loop (and caps any subprocess timeout at the remaining budget), so the
# whole deterministic scan reliably finishes well under the canary while any
# truncated collector self-reports status!='ok' (-> partial banner + scope
# ledger disclosure, SAFE-08). 95 s is the COLLECTOR-phase budget: with the
# walker (~1 s), the stack adapters, and the render/secret-lint/write tail
# (seconds on a large monorepo) layered on top, the whole `repo-audit scan --no-agent` finishes
# comfortably under the 120 s acceptance canary while staying a tight tripwire
# (well below the documented 300 s ceiling). The per-file gitleaks subprocess is
# additionally capped at the budget remaining (see secret_detection.run), so the
# collector phase cannot overshoot this deadline by a full gitleaks timeout.
TIME_BUDGET_S: float = 95.0

# Self-reference so the cross-stack SCA step can be invoked via the module
# attribute (``scan_runner.run_sca``), keeping it monkeypatchable in tests the
# same way ``run_adapters`` is.
_THIS_MODULE = sys.modules[__name__]

# W1 (T-11-07-01): the Phase-11 cross-stack steps (run_kotlin / run_expo /
# run_test_depth) may self-report ``not_applicable`` (the repo is not Kotlin / not
# Expo). A not-applicable step is DISCLOSED via a ledger note but does NOT flip
# the scan to ``partial`` — mirrors the run_mobile precedent. ``partial`` again
# means "an APPLICABLE step degraded". Anything that is neither ``ok`` nor
# ``not_applicable`` (unavailable / partial / timeout on an applicable step) is a
# genuine degradation that DOES flip partial.
_PHASE11_NON_PARTIAL_STATUSES = ("ok", "not_applicable")


def _phase11_step_degraded(status: str) -> bool:
    """True when a Phase-11 step status is a GENUINE degradation (flips partial).

    ``ok`` and ``not_applicable`` are non-degrading; everything else degrades.
    """
    return status not in _PHASE11_NON_PARTIAL_STATUSES


# Phase 16 (Plan 16-07): the CONFIG-DRIVEN deep lanes (CodeQL / DAST) are
# default-OFF opt-in lanes that, unlike the dataclass lanes, return
# ``unavailable`` (NOT ``not_applicable``) for BOTH their disclosed
# non-applicability (default-OFF / no configured target) AND a genuine
# degradation (binary absent, exec failure). The must-have is explicit: a lane
# that is OFF-by-default / has no configured target is DISCLOSED in the ledger
# but does NOT flip partial. Since these lanes cannot distinguish those cases via
# status alone — and an opt-in lane that the user never enabled is the
# overwhelmingly common case — their ``unavailable`` is treated as non-flipping
# (disclosed-not-degrading), mirroring the spirit of the Phase-11 not_applicable
# precedent. ``timeout`` / ``partial`` (the lane actually RAN and degraded) still
# flip partial. ``--no-sast`` is the deliberate counter-precedent: SAST is
# default-ON, so its ``unavailable`` DOES flip; CodeQL/DAST are default-OFF.
_PHASE16_OPTIN_NON_PARTIAL_STATUSES = ("ok", "not_applicable", "unavailable")


def _phase16_optin_lane_degraded(status: str) -> bool:
    """True when a config-driven Phase-16 opt-in lane status flips partial.

    ``ok`` / ``not_applicable`` / ``unavailable`` are non-degrading (the lane is
    OFF-by-default or has no configured target — DISCLOSED, not a degradation).
    ``timeout`` / ``partial`` (the lane ran and degraded) DO flip partial.
    """
    return status not in _PHASE16_OPTIN_NON_PARTIAL_STATUSES


@dataclass
class ScanResult:
    """Data carrier returned by :func:`run_scan`.

    Fields:
        scan_report   -- the assembled, rendered ScanReport object
        md_path       -- path of the written markdown sidecar
        json_path     -- path of the written JSON sidecar
        rc            -- return code from render_and_write (0 ok / 2 secret-lint
                         / 3 completion-honesty). When rc != 0 the sidecar pair
                         was NOT written and md_path/json_path are the intended
                         (unwritten) targets; the caller raises typer.Exit(rc).
        agent_status  -- meta.agent_status after the run (None under --no-agent,
                         'ok' on success, a D-67 fallback reason otherwise).
        offenders     -- post-flight integrity offenders (files modified outside
                         docs/state-reports/). Empty on a clean read-only run.
                         The caller echoes the INTEGRITY ALERT block from this.
        prior_sidecar -- the most-recent prior JSON sidecar before today (or
                         None for a baseline run). Plan 02/03 consume this for
                         delta computation; this plan just uses its presence to
                         drive baseline_run.
    """

    scan_report: ScanReport
    md_path: Path
    json_path: Path
    rc: int
    agent_status: str | None
    offenders: list[str] = field(default_factory=list)
    prior_sidecar: Path | None = None


def _maybe_refresh_coverage(repo_path: Path, findings: list) -> list:
    """Plan 03-05 Decision C sub-steps C + D: refresh-coverage wiring.

    Called when the user passes ``--refresh-coverage`` to ``repo-audit scan``.
    Inspects the merged findings list for a prior ``coverage_unavailable``
    Finding emitted by the lcov parser's import-only pass; if found,
    invokes plan 03-06's ``refresh_coverage`` runner and branches:

      * RefreshResult.status == 'ok' (sub-step C):
        Re-invokes ``parse_from_repo(repo_path)`` to obtain the fresh
        aggregate Finding; REPLACES the prior unavailable Finding with the
        fresh aggregate via a list comprehension that preserves the
        relative order of all other findings.

      * RefreshResult.status in {'failed', 'timeout'} (sub-step D):
        Calls plan 03-03's ``_refresh_failed_finding`` helper and APPENDS
        the returned ``evidence_type='failed'`` Finding to the merged list.
        Does NOT remove the prior unavailable Finding — the report shows
        both "no fresh artifact" AND "we tried; here's why it failed."

      * RefreshResult.status == 'skipped' or no prior unavailable Finding:
        no-op; returns the input list unchanged.

    Imports inside this function (rather than at module top) so the
    --refresh-coverage flag is the only call site that pulls in the
    refresh runner + lcov re-invoke helpers. Module-load cost stays
    bounded by the regular adapter-package import already at the top.
    """
    # Locate the previous 'unavailable' Finding emitted by the first lcov
    # parser pass (plan 03-03 contract: source_tool='lcov' AND
    # rule_id='coverage_unavailable').
    prior_unavailable = [
        f for f in findings
        if getattr(f, "source_tool", "") == "lcov"
        and getattr(f, "rule_id", "") == "coverage_unavailable"
    ]
    if not prior_unavailable:
        # Coverage was fresh on the first pass; nothing to refresh.
        return findings

    import os
    from repo_audit.adapters.typescript import CONFIG as _TS_CONFIG
    from repo_audit.adapters.typescript.parsers.lcov import (
        _refresh_failed_finding,
        parse_from_repo as _parse_lcov_from_repo,
    )
    from repo_audit.adapters.typescript.refresh import (
        refresh_coverage as _refresh_runner,
    )

    refresh_cfg = _TS_CONFIG.get("tools", {}).get("coverage_refresh", {})
    refresh_result = _refresh_runner(
        repo_root=repo_path,
        cfg=refresh_cfg,
        env=dict(os.environ),  # plan 03-06 applies the secret-scrub
    )

    if refresh_result.status == "ok":
        # Sub-step C: re-invoke lcov parser; replace the unavailable
        # Finding with the fresh aggregate (preserve order).
        fresh_findings = _parse_lcov_from_repo(repo_path)
        fresh_aggregate = next(
            (f for f in fresh_findings if getattr(f, "rule_id", "") == "coverage_summary"),
            None,
        )
        if fresh_aggregate is not None:
            return [
                fresh_aggregate if (
                    getattr(f, "source_tool", "") == "lcov"
                    and getattr(f, "rule_id", "") == "coverage_unavailable"
                ) else f
                for f in findings
            ]
        # Fresh parse did not produce an aggregate (artifact still missing
        # despite ok status — unlikely but defensive); fall through and
        # leave the unavailable Finding in place.
        return findings

    if refresh_result.status in {"failed", "timeout"}:
        # Sub-step D: synthesize a 'failed' Finding; do NOT remove the
        # prior unavailable Finding — both surface in the report.
        failed_finding = _refresh_failed_finding(
            refresh_result,
            runner_command=refresh_result.runner_command,
        )
        return findings + [failed_finding]

    # status == 'skipped' → no-op (refresh chose not to run).
    return findings


def _merge_why_it_matters(top_findings: list, agent_output) -> list:
    """Merge the agent's ``why_it_matters`` prose onto the Python-authored Top-N.

    Plan 18-03 (D-69 / T-18-08): the agent fills ONLY the ``why_it_matters`` field
    per :class:`TopFinding`; the deterministic rank/score/ids stay AUTHORITATIVE.
    This matches the agent's emitted entries to the Python list by ``finding_ref``
    and copies ACROSS ONLY the prose — never the agent's rank/composite/band/ids
    (an agent that reorders or rescores is ignored). Never raises: on any shape
    mismatch the Python list is returned unchanged (the section still renders
    deterministically, just without prose).
    """
    if not top_findings or agent_output is None:
        return top_findings
    try:
        agent_tops = list(getattr(agent_output, "top_findings", None) or [])
        if not agent_tops:
            return top_findings
        prose_by_ref: dict[str, str] = {}
        for at in agent_tops:
            ref = getattr(at, "finding_ref", "") or ""
            why = (getattr(at, "why_it_matters", "") or "").strip()
            if ref and why:
                prose_by_ref[ref] = why
        if not prose_by_ref:
            return top_findings
        merged = []
        for tf in top_findings:
            why = prose_by_ref.get(getattr(tf, "finding_ref", ""), "")
            merged.append(tf.model_copy(update={"why_it_matters": why}) if why else tf)
        return merged
    except Exception:  # noqa: BLE001 — never break the scan over a prose merge
        return top_findings


def run_scan(
    repo_path: Path,
    *,
    no_agent: bool = False,
    refresh_coverage: bool = False,
    refresh_vuln_db: bool = False,
    agent_budget: int | None = None,
    uncapped: bool = False,
    rls_runtime: bool = False,
    rls_pgrls: bool = False,
    mobsf: bool = False,
    mobsf_build: bool = False,
    apk: Path | None = None,
    sast: bool = True,
    mutation: bool = False,
    typed_detekt: bool = True,
    qd_build: bool = False,
    e2e: bool = False,
    fuzz: bool = False,
    epss: bool = False,
) -> ScanResult:
    """Run the full single-repo scan pipeline and return a :class:`ScanResult`.

    This is the single source of truth for the scan pipeline. ``repo-audit scan``
    (cli.py) and ``repo-audit fleet`` (Plan 05) both call it. It performs NO
    CLI-presentation side effects (no ``typer.echo`` / ``typer.Exit``); the
    caller surfaces rc, integrity offenders, agent status, and "Wrote ..."
    lines from the returned ``ScanResult``.

    Pipeline (every step preserved verbatim from the original cli.py::scan):
        1. overall_start timer (Phase 4 wall-clock)
        2. snapshot_git_status(repo) — BEFORE collectors (D-33 baseline)
        3. metadata: slug / head_sha / scan_date / detect_stacks
        4. build_repo_index(repo) — single shared walker (D-26)
        5. run_collectors(repo, walker.index) — sequential (D-24)
        5.5 run_adapters(repo, detection) — Phase 3 stack-adapter dispatch
        6. merge collector + adapter findings
        6.5 _maybe_refresh_coverage(...) when refresh_coverage (Decision C)
        7. build_scope_ledger(...) — REP-04 / D-30
        8. partial determination — D-31
        8.5 find_prior_sidecar → baseline_run conditional (Plan 05-01)
        9. ReportMeta assembly
        9.5 agent_budget override (AGENT-05 / D-65) — SKIPPED when uncapped
            (UNCAPPED-01: --uncapped WINS over --agent-budget)
        10. run_agent_session (unless no_agent) — D-53 / D-67
        10.5 auto_fill_ledger_gaps — AGENT-07 / D-60
        11. ScanReport assembly
        12. state_report_paths + render_and_write (D-07 / D-32)
        13. meta.wall_clock_seconds overwrite AFTER render (Pitfall 5)
        14. post-flight diff_git_status integrity tripwire (D-33 / Pitfall 7)

    Exit codes (carried on ScanResult.rc): 0 success / 2 secret-lint / 3
    completion-honesty.
    """
    # Plan 18-02 exposed ``epss`` (the --epss opt-in egress gate) as an
    # accept-and-hold parameter; Plan 18-03 threads it into
    # ``run_synthesis(..., epss_enabled=epss)`` at the synthesis call site below
    # (after run_verification, before build_scope_ledger).

    repo_path = Path(repo_path).resolve()
    overall_start = time.perf_counter()  # overall scan wall-clock

    # D-33 pre-flight snapshot (must happen BEFORE any collector reads).
    pre_status = snapshot_git_status(repo_path)

    # Metadata (D-12).
    slug = repo_slug(repo_path)
    try:
        commit_sha = head_sha(repo_path)
    except NotAGitRepo:
        commit_sha = UNCOMMITTED_MARKER
    scan_date = _date.today()
    detection = detect_stacks(repo_path)

    # D-26 walker — single in-memory index, fed to every collector.
    walker_result = build_repo_index(repo_path)

    # D-24 sequential collector orchestration.
    # SCAN-BOUND-01 (D-051-06): pass the per-scan deadline so any overrun
    # marks remaining collectors timeout deterministically (flips partial).
    collector_results = run_collectors(
        repo_path, walker_result.index,
        deadline=overall_start + TIME_BUDGET_S,
    )

    # Phase 3 (Plan 03-05): adapter dispatch between collectors and ledger.
    # Called via the module attribute so it stays patchable in tests.
    adapter_results = run_adapters(repo_path, detection)

    # Phase 7 (Plan 07-05): CROSS-STACK SCA step (RESEARCH Open Q1). Unlike
    # run_adapters (per-stack dispatch), SCA runs ONCE per repo regardless of
    # the detected stacks, so it is its OWN step. osv is the floor + grype is
    # optional; the persistent DB-cache env (build_sca_env) is layered INSIDE
    # run_sca on top of the per-scan tempdir env we build here. Called via the
    # module attribute so it stays patchable in tests. --refresh-vuln-db is the
    # sole snapshot-advance path (threaded to run_sca(refresh=...)).
    with scan_tempdir() as _sca_td:
        sca_base_env = build_scan_env(_sca_td)
        # Reference via the module so tests can monkeypatch
        # scan_runner.run_sca (same patchable-attribute pattern as run_adapters).
        sca_result = _THIS_MODULE.run_sca(
            repo_path, base_env=sca_base_env, refresh=refresh_vuln_db
        )

    # Phase 12 (Plan 12-05): CROSS-STACK SUPPLY-CHAIN step (mirrors the Phase 7
    # SCA step). Composes HIST-01 (full-history secrets) + SUP-01 (MAL-*
    # promotion over the SCA finding set) + SUP-02 (CycloneDX SBOM) + SCA-04
    # (license + deprecated) into ONE never-raising envelope. It runs RIGHT AFTER
    # run_sca (it shares SCA lineage — it consumes sca_result.findings for the
    # MAL-* promotion) and OUTSIDE the 95 s collector deadline (Pitfall 3: the
    # full-history walk + Syft each carry their own generous internal timeout).
    # It receives the COLL-03 working-tree finding set so HIST-01 dedups a
    # still-present secret against the working tree (only net-new committed-then-
    # deleted secrets surface). Called via the module attribute so tests can
    # monkeypatch scan_runner.run_supply_chain (same patchable pattern as run_sca).
    working_tree_findings = [
        f for r in collector_results for f in r.findings
    ]
    with scan_tempdir() as _sc_td:
        sc_base_env = build_scan_env(_sc_td)
        supply_chain_result = _THIS_MODULE.run_supply_chain(
            repo_path,
            base_env=sc_base_env,
            scan_date=scan_date,
            working_tree_findings=working_tree_findings,
            sca_findings=sca_result.findings,
        )

    # Phase 13 (Plan 13-04): CROSS-STACK CI/CD step (mirrors the Phase 12
    # supply-chain step). Composes CICD-01 (zizmor + actionlint over
    # .github/workflows) + CICD-02 (hadolint per-Dockerfile + framework-scoped
    # checkov over IaC) into ONE never-raising CicdScanResult envelope. It runs
    # AFTER run_supply_chain and OUTSIDE the 95 s collector deadline (each
    # sub-collector carries its own generous run_tool timeout). The scan_tempdir
    # is REQUIRED so checkov's results_sarif.sarif lands OUTSIDE the read-only
    # target repo (REP-03 / T-13-WRITE). A repo with no .github/workflows + no
    # Dockerfile + no IaC degrades to status='not_applicable' — DISCLOSED via the
    # ledger but NON-partial-flipping (D-13-05, via _phase11_step_degraded);
    # an applicable degradation (tool absent when files present, timeout) flips
    # partial. Called via _THIS_MODULE so tests can monkeypatch scan_runner.run_cicd
    # (same patchable-attribute pattern as run_sca / run_supply_chain).
    with scan_tempdir() as _cicd_td:
        cicd_base_env = build_scan_env(_cicd_td)
        cicd_result = _THIS_MODULE.run_cicd(repo_path, base_env=cicd_base_env)

    # Phase 14 (Plan 14-04): CROSS-STACK ARCHITECTURE step (mirrors the Phase 13
    # CI/CD step). Composes ARCH-01 (dependency-cruiser circular/boundary over the
    # JS/TS dependency graph) + ARCH-02 (jscpd copy-paste duplication, repo-wide)
    # into ONE never-raising ArchitectureScanResult envelope. It runs AFTER run_cicd
    # and OUTSIDE the 95 s collector deadline (depcruise + jscpd over a large
    # monorepo can exceed it — each sub-collector carries its own generous run_tool
    # timeout). The scan_tempdir is REQUIRED so depcruise's shipped ruleset +
    # jscpd's JSON report land OUTSIDE the read-only target repo (REP-03). The
    # already-computed ``detection`` is REUSED (detection is NOT re-run inside the
    # adapter): its stack TAGS gate ARCH-01 applicability via has_js_dependency_graph.
    # A non-JS repo degrades to status='not_applicable' — DISCLOSED via the ledger
    # but NON-partial-flipping (D-13-05, via _phase11_step_degraded); an applicable
    # degradation (tool absent on a JS stack, timeout) flips partial. Called via
    # _THIS_MODULE so tests can monkeypatch scan_runner.run_architecture (same
    # patchable-attribute pattern as run_cicd / run_sca / run_supply_chain).
    with scan_tempdir() as _arch_td:
        arch_base_env = build_scan_env(_arch_td)
        arch_result = _THIS_MODULE.run_architecture(
            repo_path,
            base_env=arch_base_env,
            stacks=[s.stack for s in detection.stacks],
        )

    # Phase 15 (Plan 15-04): CROSS-STACK QUALITY-DEPTH step (mirrors the Phase 14
    # ARCHITECTURE step). Composes A11Y-01 (axe-core runtime a11y, live-URL gated)
    # + PERF-01 (Lighthouse web perf, live-URL gated; RN bundle size, RN-surface
    # gated + opt-in --qd-build Metro build) into ONE never-raising
    # QualityDepthScanResult envelope. It runs AFTER run_architecture and OUTSIDE
    # the 95 s collector deadline (a live axe/Lighthouse pass + a Metro build each
    # take minutes — each sub-collector carries its own generous run_tool timeout).
    # The scan_tempdir is REQUIRED so axe/Lighthouse output + the RN bundle land
    # OUTSIDE the read-only target repo (REP-03). The already-computed ``detection``
    # is REUSED: its stack TAGS gate the RN-bundle sub-step via has_rn_surface; the
    # web (axe/lighthouse) sub-steps are gated by a configured ``live_url`` (read by
    # the composite from .repo-audit.yaml). A repo with NEITHER a live_url NOR
    # an RN surface degrades to status='not_applicable' — DISCLOSED via the ledger
    # but NON-partial-flipping (D-13-05, via _phase11_step_degraded); an applicable
    # degradation (axe absent when a URL is configured, a failed RN build) flips
    # partial. --qd-build (default off, never fleet-wide) is threaded through so the
    # opt-in throwaway Metro build only runs when explicitly requested. Called via
    # _THIS_MODULE so tests can monkeypatch scan_runner.run_quality_depth (same
    # patchable-attribute pattern as run_architecture / run_cicd / run_sca).
    #
    # Plan 15-05 (PERF-01 SC2): resolve the prior sidecar HERE — BEFORE the
    # quality-depth step — and extract the prior carrier bytes so the per-scan
    # web_transfer_regression / rn_bundle_regression Findings can fire. This is
    # the SAME prior_sidecar the cross-scan TrendDelta block below consumes (one
    # resolution, one defensive parse) and the SAME carrier extractors
    # (_web_transfer_metric / _rn_bundle_metric) compute_trend uses — NOT a second
    # sidecar reader. None-not-0 honesty: no prior sidecar, an unavailable carrier,
    # or a corrupt/raced prior all degrade the prior bytes to None → NO regression
    # Finding (never a fabricated zero baseline). The parsed prior report is reused
    # by the TrendDelta block below.
    prior_sidecar = find_prior_sidecar(repo_path, scan_date)
    prior_report: ScanReport | None = None
    prior_web_bytes: int | None = None
    prior_rn_bytes: int | None = None
    if prior_sidecar is not None:
        try:
            prior_report = ScanReport.model_validate_json(
                prior_sidecar.read_text(encoding="utf-8")
            )
            prior_web_bytes = _web_transfer_metric(prior_report)
            prior_rn_bytes = _rn_bundle_metric(prior_report)
        except Exception:  # noqa: BLE001 — a corrupt/raced prior must not crash
            prior_report = None
            prior_web_bytes = None
            prior_rn_bytes = None

    with scan_tempdir() as _qd_td:
        qd_base_env = build_scan_env(_qd_td)
        qd_result = _THIS_MODULE.run_quality_depth(
            repo_path,
            base_env=qd_base_env,
            stacks=[s.stack for s in detection.stacks],
            qd_build=qd_build,
            prior_web_bytes=prior_web_bytes,
            prior_rn_bytes=prior_rn_bytes,
        )

    # Phase 8 (Plan 08-05): CROSS-STACK RLS step (mirrors the Phase 7 SCA step).
    # Like run_sca, run_supabase runs ONCE per repo (the ephemeral-DB lifecycle +
    # the --rls-pgrls / --rls-runtime flag gating sit ABOVE per-stack dispatch),
    # so it is its OWN step right after run_sca and BEFORE the findings merge.
    # splinter is the always-on floor; pgrls runs only when --rls-pgrls; the
    # runtime two-account probe runs only when --rls-runtime (and its own
    # six-name gate). Called via the module attribute so tests can monkeypatch
    # scan_runner.run_supabase (same patchable-attribute pattern as run_sca).
    with scan_tempdir() as _rls_td:
        rls_base_env = build_scan_env(_rls_td)
        rls_result = _THIS_MODULE.run_supabase(
            repo_path,
            base_env=rls_base_env,
            rls_pgrls=rls_pgrls,
            rls_runtime=rls_runtime,
        )

    # Phase 9 (Plan 09-05): CROSS-STACK MOBILE step (mirrors the Phase 7 SCA +
    # Phase 8 RLS steps). Like them, run_mobile runs ONCE per repo — the
    # --mobsf / --mobsf-build / --apk flag gating sits ABOVE per-stack dispatch.
    # Tier-1 mobsfscan + Tier-2 bundled-secrets run by DEFAULT (no build, no
    # Docker); Tier-3a MobSF runs only when --mobsf + an APK; Tier-3b
    # assembleDebug runs only when --mobsf-build. Called via the module attribute
    # so tests can monkeypatch scan_runner.run_mobile (same patchable pattern).
    with scan_tempdir() as _mob_td:
        mob_base_env = build_scan_env(_mob_td)
        mob_result = _THIS_MODULE.run_mobile(
            repo_path,
            base_env=mob_base_env,
            mobsf=mobsf,
            mobsf_build=mobsf_build,
            apk=apk,
        )

    # Phase 10 (Plan 10-04): CROSS-STACK SAST step (mirrors the Phase 7 SCA +
    # Phase 8 RLS + Phase 9 Mobile steps). Like them, run_sast runs ONCE per repo
    # regardless of the detected stacks — it selects the Semgrep ruleset packs
    # from `detection` (always p/owasp-top-ten + p/secrets; +p/typescript /
    # +p/react per stack), runs collect_semgrep under a per-scan tempdir scan env,
    # and stamps a D-10-02 FeedProvenance entry (runtime-fetch; db_snapshot_date
    # =None). Default ON; --no-sast skips it (degrades to a benign 'unavailable'
    # SastScanResult so the dimension is honestly disclosed). Called via the
    # module attribute so tests can monkeypatch scan_runner.run_sast (same
    # patchable-attribute pattern as run_sca / run_supabase / run_mobile).
    if sast:
        with scan_tempdir() as _sast_td:
            sast_base_env = build_scan_env(_sast_td)
            sast_result = _THIS_MODULE.run_sast(
                repo_path, base_env=sast_base_env, detection=detection
            )
    else:
        from repo_audit.adapters.sast import SastScanResult
        sast_result = SastScanResult(
            status="unavailable", notes="SAST skipped (--no-sast)"
        )

    # Phase 11 (Plan 11-05): THREE CROSS-STACK STEPS mirroring run_sast — the
    # Kotlin/detekt step (run_kotlin), the Expo/expo-doctor step (run_expo), and
    # the cross-stack test-depth step (run_test_depth: coverage + mutation +
    # type-coverage). Each is a never-raising envelope: status folds into
    # `partial`, findings merge below, notes/ledger_notes fold into the scope
    # ledger (SAFE-08). Mutation is OPT-IN only (D-11-03): run_test_depth receives
    # `mutation=mutation` which DEFAULTS False here — only the CLI --mutation flag
    # sets it True, so a fleet sweep (run_scan(no_agent=True)) never runs Stryker.
    # Called via _THIS_MODULE so tests can monkeypatch the steps (same patchable-
    # attribute pattern as run_sca / run_supabase / run_mobile / run_sast).
    #
    # Stack selection for run_test_depth: the PRIMARY detected stack drives the
    # coverage runner + artifact. The Phase-3 `--refresh-coverage` lcov refresh
    # already handles the TypeScript/Expo/RN (node) stacks via
    # `_maybe_refresh_coverage` below, so run_test_depth's coverage tier is gated
    # to NON-node stacks (python/kotlin) to avoid a double coverage run / a
    # duplicate coverage Finding. The mutation + type-coverage tiers run
    # regardless of stack (mutation only under --mutation; type-coverage is
    # read-only and self-degrades to unavailable when the tool is absent).
    # W5: _NODE_STACKS is imported from refresh (single source of truth shared by
    # this routing gate AND refresh's coverage-runner resolution) — no inline copy.
    primary_stack = (
        detection.stacks[0].stack if detection.stacks else "typescript-node"
    )
    td_refresh_coverage = refresh_coverage and primary_stack not in _NODE_STACKS

    # B3 (D-11-06 reach): the node lcov coverage_summary Finding is produced by
    # `_maybe_refresh_coverage` (called at the findings-merge step BELOW, after
    # run_test_depth). For a node stack run with BOTH --refresh-coverage AND
    # --mutation, run that node coverage refresh FIRST so its executed line_pct can
    # be threaded into run_test_depth's mutation tier (the in-step coverage tier is
    # gated OFF for node stacks to avoid a double coverage run). We refresh against
    # the findings produced so far (collectors + adapters carry the lcov
    # `coverage_unavailable` Finding that _maybe_refresh_coverage keys on), reuse
    # the SAME refreshed list below (a flag skips the second call), and extract the
    # node line_pct from the refreshed `coverage_summary` Finding. NEVER double-runs
    # the coverage refresh — the original no-double-run intent is preserved.
    node_mutation_path = (
        refresh_coverage and mutation and primary_stack in _NODE_STACKS
    )
    injected_line_pct: float | None = None
    coverage_refreshed_early = False
    refreshed_node_findings: list | None = None
    if node_mutation_path:
        # The findings list the refresh keys on (collectors + adapters carry the
        # lcov coverage Findings). SCA/RLS/mobile/SAST findings are appended below;
        # the coverage refresh only inspects/rewrites the lcov coverage Finding, so
        # refreshing against this prefix is sufficient and order-preserving.
        pre_refresh_node_findings = (
            [f for r in collector_results for f in r.findings]
            + [f for r in adapter_results for f in r.findings]
        )
        refreshed_node_findings = _maybe_refresh_coverage(
            repo_path, pre_refresh_node_findings
        )
        coverage_refreshed_early = True
        injected_line_pct = next(
            (
                f.evidence.parsed_value.get("line_pct")
                for f in refreshed_node_findings
                if getattr(f, "rule_id", "") == "coverage_summary"
                and isinstance(
                    getattr(getattr(f, "evidence", None), "parsed_value", {}).get(
                        "line_pct"
                    ),
                    (int, float),
                )
            ),
            None,
        )

    with scan_tempdir() as _kot_td:
        kot_base_env = build_scan_env(_kot_td)
        kotlin_result = _THIS_MODULE.run_kotlin(
            repo_path, base_env=kot_base_env, attempt_typed=typed_detekt
        )
    with scan_tempdir() as _expo_td:
        expo_base_env = build_scan_env(_expo_td)
        expo_result = _THIS_MODULE.run_expo(repo_path, base_env=expo_base_env)
    with scan_tempdir() as _td_td:
        td_base_env = build_scan_env(_td_td)
        test_depth_result = _THIS_MODULE.run_test_depth(
            repo_path,
            base_env=td_base_env,
            refresh_coverage=td_refresh_coverage,
            mutation=mutation,
            stack=primary_stack,
            injected_line_pct=injected_line_pct,
        )

    # Phase 16 (Plan 16-07): FIVE NEW DYNAMIC/DEEP LANES wired exactly like the
    # Phase-11 cross-stack steps — each under its OWN ``scan_tempdir`` (scratch
    # OUTSIDE the read-only repo, REP-03 / T-16-07-02) and dispatched via
    # ``_THIS_MODULE.<name>`` so tests monkeypatch the lane functions (no live
    # tools needed). Findings merge below; status folds into ``partial`` via
    # ``_phase11_step_degraded`` (a not_applicable lane — no harness / no target /
    # default-OFF — is DISCLOSED in the ledger but does NOT flip partial); notes
    # fold into the scope ledger (SAFE-08). The heavy E2E/fuzz lanes are opt-in
    # ONLY: ``e2e``/``fuzz`` default OFF here so a fleet sweep
    # (run_scan(no_agent=True)) never runs them (T-16-07-03, mirrors --mutation).
    # CodeQL/DAST/commercial are config-driven (default-OFF behind attestation /
    # a configured target URL) — no CLI flag.
    #
    # Config readers (load_codeql_config / load_byo_config) can raise a pydantic
    # ValidationError on a MALFORMED opt-in block (fail-loud by design). run_scan
    # must NEVER raise (D-25), so each config read is wrapped defensively: a
    # malformed block degrades the lane to absent (None / {}) and is disclosed via
    # a ledger note rather than crashing the scan. read_dast_config already never
    # raises (it degrades to documented defaults).
    _yaml_path = repo_path / ".repo-audit.yaml"
    _lane_cfg_notes: list[str] = []
    try:
        codeql_cfg = load_codeql_config(_yaml_path)
    except Exception as exc:  # noqa: BLE001 — a malformed opt-in block must not crash
        codeql_cfg = None
        _lane_cfg_notes.append(
            f"CodeQL config ignored (malformed): {type(exc).__name__}"
        )
    try:
        _byo_all = load_byo_config(_yaml_path)
    except Exception as exc:  # noqa: BLE001
        _byo_all = {}
        _lane_cfg_notes.append(
            f"BYO commercial config ignored (malformed): {type(exc).__name__}"
        )
    # The commercial slice of the BYO config = entries whose name is one of the
    # five first-class commercial tools (the rest of byo_tools is the generic
    # BYO-01 pattern, not the BYO-02 commercial wrappers).
    commercial_configs = {
        name: cfg for name, cfg in _byo_all.items() if name in COMMERCIAL_TOOLS
    }

    with scan_tempdir() as _e2e_td:
        e2e_base = build_scan_env(_e2e_td)
        # infra_present=False: a built app + booted device/browser is absent on
        # this machine → the lane degrades to detected-not-run (D-16-02).
        e2e_result = _THIS_MODULE.run_e2e(
            repo_path, base_env=e2e_base, opt_in=e2e, infra_present=False
        )
    with scan_tempdir() as _fuzz_td:
        fuzz_base = build_scan_env(_fuzz_td)
        fuzz_result = _THIS_MODULE.run_fuzz(
            repo_path, base_env=fuzz_base, opt_in=fuzz
        )
    with scan_tempdir() as _cq_td:
        cq_base = build_scan_env(_cq_td)
        codeql_result = _THIS_MODULE.run_codeql(
            repo_path,
            base_env=cq_base,
            cfg=codeql_cfg,
            scratch_dir=_cq_td,
            detection=detection,
        )
    with scan_tempdir() as _dast_td:
        dast_base = build_scan_env(_dast_td)
        # opt_in=True: providing the configured target_url IS the opt-in
        # (D-16-10); with no target_url the lane refuses + degrades to
        # unavailable WITHOUT a subprocess.
        dast_result = _THIS_MODULE.run_dast(
            repo_path,
            base_env=dast_base,
            opt_in=True,
            scratch_dir=_dast_td,
            cfg=read_dast_config(repo_path),
        )
    with scan_tempdir() as _byo_td:
        byo_base = build_scan_env(_byo_td)
        byo_commercial_result = _THIS_MODULE.run_byo_commercial(
            repo_path,
            base_env=byo_base,
            scratch_dir=_byo_td,
            configs=commercial_configs,
        )

    # Aggregate findings across collectors + adapters + SCA + RLS (sequential
    # preserves ledger order). SCA + RLS findings are appended deterministically
    # so SC-5 determinism holds. Built BEFORE the refresh sub-steps below so the
    # sub-steps can rewrite/extend this list.
    #
    # B3 no-double-run: when the node+mutation path already ran
    # `_maybe_refresh_coverage` above (to thread the node line_pct into the
    # mutation tier), reuse its refreshed collector+adapter prefix here instead of
    # refreshing a second time. Otherwise build the prefix fresh and let the
    # refresh sub-step below run as usual.
    if coverage_refreshed_early and refreshed_node_findings is not None:
        collector_adapter_prefix = list(refreshed_node_findings)
    else:
        collector_adapter_prefix = (
            [f for r in collector_results for f in r.findings]
            + [f for r in adapter_results for f in r.findings]
        )
    # Phase 12 (Plan 12-05) — CVE-PARTITION CORRECTNESS (Open Q1 / T-12-05-DIL):
    # the SCA findings merged into the aggregate use the MAL-FREE
    # `supply_chain_result.cve_findings` (NOT `sca_result.findings`, which still
    # carries the un-promoted MAL-* findings). The promoted MAL-* (confidence=
    # 'confirmed') enters ONCE via `supply_chain_result.findings` (alongside the
    # history + license findings). This guarantees each MAL advisory is counted
    # exactly once and never double-counted across the CVE partition + the
    # promotion. The SCA `partition` built inside run_sca over sca_result.findings
    # is RENDERING-ONLY (headline/appendix shaping); this merged finding set is
    # the AUTHORITATIVE one. partition.py is untouched.
    findings = (
        collector_adapter_prefix
        + list(supply_chain_result.cve_findings)
        + list(supply_chain_result.findings)
        + list(rls_result.findings)
        + list(mob_result.findings)
        + list(sast_result.findings)
        + list(kotlin_result.findings)
        + list(expo_result.findings)
        + list(test_depth_result.findings)
        + list(cicd_result.findings)
        + list(arch_result.findings)
        + list(qd_result.findings)
        # Phase 16 (Plan 16-07): the five dynamic/deep lanes, appended in
        # deterministic order (SC-5) after every prior step.
        + list(e2e_result.findings)
        + list(fuzz_result.findings)
        + list(codeql_result.findings)
        + list(dast_result.findings)
        + list(byo_commercial_result.findings)
    )

    # Phase 16 (Plan 16-07) — SCAN-RUNNER-LEVEL DAST RUNTIME POST-PASS GUARD
    # (D-16-12 / SAFE-01 / T-16-07-01). Defence-in-depth complementing the
    # per-lane guard in dast/__init__.py: NO merged DAST finding may carry
    # evidence_type='runtime' (runtime is reserved for the Phase-8 Supabase
    # two-account test — the sole legitimate runtime emitter). A DAST finding
    # that somehow reached the merged set tagged 'runtime' is a false-confidence
    # breach: it is DROPPED here and a SAFE-01 violation note is folded into the
    # ledger below. This MUST NOT raise across run_scan (D-25 never-raise
    # contract): the invariant is expressed as a guarded assert so a maintainer
    # who reads it understands the contract, but any AssertionError is caught,
    # the offending finding is dropped, and the scan completes + returns a
    # ScanResult. We identify DAST findings by source_tool (the DAST lane stamps
    # a fixed source_tool on every finding it emits).
    _dast_source_tools = {f.source_tool for f in dast_result.findings}
    _dast_runtime_violations: list = []
    if _dast_source_tools:
        kept_findings: list = []
        for f in findings:
            is_dast = getattr(f, "source_tool", None) in _dast_source_tools
            if is_dast and getattr(f, "evidence_type", None) == "runtime":
                try:
                    # Express the invariant as an assert (documentation +
                    # contract), but NEVER let it crash run_scan.
                    assert f.evidence_type != "runtime", (
                        "DAST finding must never be runtime (D-16-12/SAFE-01)"
                    )
                except AssertionError:
                    _dast_runtime_violations.append(f)
                continue  # drop the offending runtime-tagged DAST finding
            kept_findings.append(f)
        findings = kept_findings

    # Sub-step C + D: --refresh-coverage opt-in wiring (D-41' / Decision A).
    # Runs BEFORE build_scope_ledger so the ledger reflects the
    # post-refresh findings state. Sub-step C replaces the lcov
    # 'coverage_unavailable' Finding with the fresh aggregate on refresh
    # success; sub-step D appends a 'coverage_refresh_failed' Finding on
    # refresh failure (does NOT remove the unavailable Finding — both
    # surface so the reader sees "no fresh artifact" AND "we tried; here's
    # why it failed").
    #
    # B3 no-double-run: skip when the node+mutation path already ran the refresh
    # above (its result is already folded into `collector_adapter_prefix`).
    if refresh_coverage and not coverage_refreshed_early:
        findings = _maybe_refresh_coverage(repo_path, findings)

    # Phase 17 (Plan 17-03) — VERIFICATION STAGE (VER-01 / SC1 / Pitfall 1).
    # Inserted AFTER the DAST runtime post-pass guard (+ refresh-coverage) and
    # BEFORE build_scope_ledger so the ledger, narrator, and renderer all consume
    # the POST-verification finding set. run_verification orchestrates:
    #   stage-1 tiered_corroborate (candidate -> corroborated, RAISES only)
    #   stage-2 the adversarial critic (skipped under --no-agent via no_critic)
    #   confirmed gate (corroborated AND survived -> confirmed; runtime auto-
    #     confirms without a critic run; non-runtime corroborated-without-critic
    #     stays corroborated)
    #   refuted appendix (valid refutation -> refuted[], never vanishes, D-17-14)
    #   downgrade-only post-pass (no static->runtime promotion survives, D-17-16)
    # The call is dispatched through the module attribute (_verification) so the
    # stage is patchable in tests without the live SDK (mirrors the narrator's
    # _agent_session indirection at L1160). run_verification is NEVER-RAISE (D-25):
    # any failure leaves findings at their deterministic rungs and the scan
    # completes. The render chokepoint is untouched — verification is a SEPARATE
    # stage whose OUTPUT later renders (so the render-time secret-lint still applies
    # to the refuted appendix).
    from repo_audit.verification import stage as _verification
    (
        findings,
        _refuted_findings,
        _verification_records,
        _verification_meta,
    ) = _verification.run_verification(
        findings, repo_path=repo_path, no_critic=no_agent, uncapped=uncapped
    )

    # Phase 18 (Plan 18-03) — SYNTHESIS STAGE (SYN-01/02 / D-18-09 / D-18-10).
    # Inserted AFTER run_verification and BEFORE build_scope_ledger so the ledger,
    # narrator, and renderer all consume the POST-synthesis ranking. run_synthesis
    # scores → ranks → selects the no-pad Top-N, fusing the bundled offline KEV
    # band + (opt-in) EPSS. The --epss boolean threads through here
    # (epss_enabled=epss); a per-repo config epss_enabled:true is OR'd inside.
    # Dispatched through the module attribute (_synthesis) so the stage is
    # patchable in tests (mirrors _verification / _agent_session). run_synthesis is
    # NEVER-RAISE (D-25): any failure leaves findings unranked-but-present and the
    # scan completes. build_top_findings then maps the ranked shortlist into the
    # Python-authored TopFinding list (rank/score/ids authoritative — D-69); the
    # narrator later fills ONLY why_it_matters per item.
    from repo_audit.synthesis import stage as _synthesis
    from repo_audit.synthesis.topfinding import build_top_findings
    (
        findings,
        _synthesis_scores_by_token,
        _synthesis_top_data,
        _synthesis_meta,
    ) = _synthesis.run_synthesis(
        findings,
        _verification_records,
        repo_path=repo_path,
        epss_enabled=epss,
        # 18-02 CR-01: thread the post-verification identity tokens (parallel to the
        # refuted-filtered ``findings``) so synthesis pairs each surviving finding to
        # its OWN VerificationRecord by ``candidate_token``, never by list position.
        active_tokens=_verification_meta.get("active_tokens"),
    )
    top_findings = build_top_findings(_synthesis_top_data)
    # The paired PriorityScore list (token order) feeds the AllowedNumbers fold so
    # a why_it_matters citing a factor magnitude survives the faithfulness gate.
    top_scores = [score for (_t, _f, score) in _synthesis_top_data if score is not None]

    # D-30 scope ledger assembly (Phase 3: adapter_results folded).
    scope_ledger = build_scope_ledger(
        walker_result, collector_results,
        repo_path=repo_path,
        adapter_results=adapter_results,
    )

    # D-31 partial-scan determination (Phase 3: adapter status considered;
    # Phase 7: SCA dimension unavailable also flips partial — Phase 2
    # graceful-degradation contract). osv-unavailable disclosed via the scope
    # ledger notes below; the scan still completes.
    #
    # W1 (T-11-07-01): a Phase-11 step that self-reports ``not_applicable`` (the
    # repo is not Kotlin / not Expo) is DISCLOSED via a ledger note but does NOT
    # flip the scan to partial — mirrors the run_mobile precedent (see
    # `_phase11_step_degraded`). ``partial`` again means "an APPLICABLE step
    # degraded", not "this repo isn't Kotlin". A genuine degradation
    # (unavailable/partial/timeout on an applicable step) still flips.
    partial = (
        walker_result.status != "ok"
        or any(r.status != "ok" for r in collector_results)
        or any(r.status != "ok" for r in adapter_results)
        or sca_result.status != "ok"
        or rls_result.status != "ok"
        or mob_result.status != "ok"
        or sast_result.status != "ok"
        # Phase 12: an APPLICABLE supply-chain degradation flips partial; a
        # not_applicable step is disclosed but does NOT flip (mirrors the
        # Phase-11 precedent via _phase11_step_degraded). The supply-chain step
        # is always applicable in practice, but honor not_applicable for parity.
        or _phase11_step_degraded(supply_chain_result.status)
        or _phase11_step_degraded(kotlin_result.status)
        or _phase11_step_degraded(expo_result.status)
        or _phase11_step_degraded(test_depth_result.status)
        # Phase 13: an APPLICABLE CI/CD degradation (tool absent when files
        # present, timeout) flips partial; a not_applicable (no CI/CD files) step
        # is DISCLOSED but does NOT flip — the D-13-05 first-class degrade, via
        # _phase11_step_degraded (which swallows not_applicable).
        or _phase11_step_degraded(cicd_result.status)
        # Phase 14: an APPLICABLE architecture degradation (depcruise/jscpd absent
        # on a JS stack, timeout) flips partial; a not_applicable (non-JS stack —
        # no JS/TS dependency graph) step is DISCLOSED but does NOT flip — the
        # first-class degrade, via _phase11_step_degraded (which swallows
        # not_applicable).
        or _phase11_step_degraded(arch_result.status)
        # Phase 15: an APPLICABLE quality-depth degradation (axe/lighthouse absent
        # when a live_url is configured, a failed RN bundle build/measure, a
        # timeout) flips partial; a not_applicable (no live_url AND no RN surface)
        # step is DISCLOSED but does NOT flip — the first-class degrade, via
        # _phase11_step_degraded (which swallows not_applicable).
        or _phase11_step_degraded(qd_result.status)
        # Phase 16: each of the five dynamic/deep lanes is a DEFAULT-OFF opt-in
        # lane. A lane in its disclosed off/no-target state is DISCLOSED via a
        # ledger note but does NOT flip partial (the must-have: a default-OFF lane
        # never degrades the scan).
        #
        # The DATACLASS lanes (E2E / fuzz / commercial) self-report
        # ``not_applicable`` when there is no harness / native target / enabled
        # commercial tool, so the standard ``_phase11_step_degraded`` (which
        # swallows ok + not_applicable) applies: a real degradation
        # (unavailable/partial/timeout once the lane is actually applicable) flips
        # partial; the off/no-surface state does not.
        #
        # The CONFIG-DRIVEN AdapterResult lanes (CodeQL / DAST) cannot return
        # ``not_applicable`` (AdapterStatus has no such member) — they return
        # ``unavailable`` for BOTH their disclosed default-OFF / no-configured-
        # target state AND a genuine degradation. Since these are opt-in lanes the
        # user almost always leaves OFF, their ``unavailable`` is treated as
        # disclosed-not-degrading via ``_phase16_optin_lane_degraded`` (which also
        # swallows ``unavailable``); only ``timeout`` / ``partial`` (the lane RAN
        # and degraded) flips. This is the counter-precedent to default-ON SAST,
        # whose ``unavailable`` DOES flip.
        or _phase11_step_degraded(e2e_result.status)
        or _phase11_step_degraded(fuzz_result.status)
        or _phase11_step_degraded(byo_commercial_result.status)
        or _phase16_optin_lane_degraded(codeql_result.status)
        or _phase16_optin_lane_degraded(dast_result.status)
    )

    # Fold the SCA status/notes into the scope ledger so the SCA dimension's
    # availability is disclosed honestly (SAFE-08 completion-honesty). osv
    # unavailable → "SCA dimension unavailable" surfaced in the ledger.
    if sca_result.notes:
        sca_note = f"SCA ({sca_result.status}): {sca_result.notes}"
        if scope_ledger.notes:
            scope_ledger.notes += "; " + sca_note
        else:
            scope_ledger.notes = sca_note

    # Fold the RLS status + ledger notes (the D-08-05 not-run posture + the
    # D-08-09/16 reproducibility provenance) into the scope ledger so the RLS
    # dimension's availability + provenance is disclosed honestly (SAFE-08). An
    # RLS dimension unavailable (e.g. no migrations / docker down) is DISCLOSED
    # here; the scan still completes (graceful degradation).
    rls_notes = list(rls_result.ledger_notes)
    if rls_result.notes:
        rls_notes.insert(0, f"RLS ({rls_result.status}): {rls_result.notes}")
    if rls_notes:
        rls_note_text = "; ".join(rls_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + rls_note_text
        else:
            scope_ledger.notes = rls_note_text

    # Fold the MOBILE status + ledger notes (the per-tier not-run / unavailable
    # disclosures) into the scope ledger so the mobile dimension's availability
    # is disclosed honestly (SAFE-08). A tier unavailable (e.g. no native
    # source / docker down / --mobsf without an APK) is DISCLOSED here; the scan
    # still completes (graceful degradation), mirroring the RLS fold above.
    mob_notes = list(mob_result.ledger_notes)
    if mob_result.notes:
        mob_notes.insert(0, f"Mobile ({mob_result.status}): {mob_result.notes}")
    if mob_notes:
        mob_note_text = "; ".join(mob_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + mob_note_text
        else:
            scope_ledger.notes = mob_note_text

    # Fold the SAST status/notes into the scope ledger so the SAST dimension's
    # availability is disclosed honestly (SAFE-08), mirroring the SCA fold. A
    # SAST dimension unavailable/timeout (semgrep absent / offline registry /
    # --no-sast) is DISCLOSED here; the scan still completes (graceful
    # degradation) and the partial flag flips above.
    if sast_result.notes:
        sast_note = f"SAST ({sast_result.status}): {sast_result.notes}"
        if scope_ledger.notes:
            scope_ledger.notes += "; " + sast_note
        else:
            scope_ledger.notes = sast_note

    # Fold the Phase-11 Kotlin / Expo / test-depth steps' status + ledger notes
    # into the scope ledger so each dimension's availability is disclosed
    # honestly (SAFE-08), mirroring the RLS / Mobile folds. An absent tool or
    # artifact (detekt jar/JRE missing, expo-doctor absent, no coverage runner /
    # mutation opt-out / type-coverage absent) is DISCLOSED here; the scan still
    # completes (graceful degradation) and the partial flag flips above.
    for _label, _res in (
        ("Kotlin", kotlin_result),
        ("Expo", expo_result),
        ("Test-depth", test_depth_result),
    ):
        _notes = list(_res.ledger_notes)
        if _res.notes:
            _notes.insert(0, f"{_label} ({_res.status}): {_res.notes}")
        if _notes:
            _note_text = "; ".join(_notes)
            if scope_ledger.notes:
                scope_ledger.notes += "; " + _note_text
            else:
                scope_ledger.notes = _note_text

    # Fold the Phase-12 SUPPLY-CHAIN step's status + ledger notes into the scope
    # ledger so every sub-step's availability is disclosed honestly (SAFE-08),
    # mirroring the RLS / Mobile / Phase-11 folds. An unavailable SBOM, an
    # offline license/deprecated pass, or a no-git history walk is DISCLOSED here
    # under the "Supply-chain" label; the scan still completes (graceful
    # degradation) and the partial flag flips above.
    sc_notes = list(supply_chain_result.ledger_notes)
    if supply_chain_result.notes:
        sc_notes.insert(
            0, f"Supply-chain ({supply_chain_result.status}): {supply_chain_result.notes}"
        )
    if sc_notes:
        sc_note_text = "; ".join(sc_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + sc_note_text
        else:
            scope_ledger.notes = sc_note_text

    # Fold the Phase-13 CI/CD step's status + ledger notes into the scope ledger
    # so every sub-tool's availability is disclosed honestly (SAFE-08), mirroring
    # the Supply-chain / Phase-11 folds. An absent tool (zizmor / actionlint /
    # hadolint / checkov missing while files present), a timeout, or a no-CI/CD-
    # files not_applicable is DISCLOSED here under the "CI/CD" label; the scan
    # still completes (graceful degradation) and the partial flag flips above only
    # for an APPLICABLE degradation.
    cicd_notes = list(cicd_result.ledger_notes)
    if cicd_result.notes:
        cicd_notes.insert(0, f"CI/CD ({cicd_result.status}): {cicd_result.notes}")
    if cicd_notes:
        cicd_note_text = "; ".join(cicd_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + cicd_note_text
        else:
            scope_ledger.notes = cicd_note_text

    # Fold the Phase-14 ARCHITECTURE step's status + ledger notes into the scope
    # ledger so every sub-tool's availability is disclosed honestly (SAFE-08),
    # mirroring the CI/CD / Supply-chain folds. An absent tool (dependency-cruiser /
    # jscpd missing on a JS stack), a timeout, or a non-JS-stack not_applicable is
    # DISCLOSED here under the "Architecture" label; the scan still completes
    # (graceful degradation) and the partial flag flips above only for an APPLICABLE
    # degradation.
    arch_notes = list(arch_result.ledger_notes)
    if arch_result.notes:
        arch_notes.insert(0, f"Architecture ({arch_result.status}): {arch_result.notes}")
    if arch_notes:
        arch_note_text = "; ".join(arch_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + arch_note_text
        else:
            scope_ledger.notes = arch_note_text

    # Fold the Phase-15 QUALITY-DEPTH step's status + ledger notes into the scope
    # ledger so every sub-tool's availability is disclosed honestly (SAFE-08),
    # mirroring the Architecture / CI/CD folds. An absent tool (axe / lighthouse
    # missing when a live_url is configured, react-native missing on an RN stack),
    # a timeout, or a no-surface (no live_url AND no RN) not_applicable is DISCLOSED
    # here under the "Quality-depth" label; the scan still completes (graceful
    # degradation) and the partial flag flips above only for an APPLICABLE
    # degradation.
    qd_notes = list(qd_result.ledger_notes)
    if qd_result.notes:
        qd_notes.insert(0, f"Quality-depth ({qd_result.status}): {qd_result.notes}")
    if qd_notes:
        qd_note_text = "; ".join(qd_notes)
        if scope_ledger.notes:
            scope_ledger.notes += "; " + qd_note_text
        else:
            scope_ledger.notes = qd_note_text

    # Fold the Phase-16 dynamic/deep lanes' status + ledger notes into the scope
    # ledger so each lane's availability is disclosed honestly (SAFE-08),
    # mirroring the Quality-depth / Architecture folds. A not_applicable lane (no
    # harness / no native target / no configured DAST target / all-default-OFF
    # commercial) is DISCLOSED here but does NOT flip partial (above). codeql's
    # AdapterResult carries no ``ledger_notes`` field — getattr defaults to [].
    for _label, _res in (
        ("E2E", e2e_result),
        ("Fuzz", fuzz_result),
        ("CodeQL", codeql_result),
        ("DAST", dast_result),
        ("Commercial", byo_commercial_result),
    ):
        _notes = list(getattr(_res, "ledger_notes", []) or [])
        if _res.notes:
            _notes.insert(0, f"{_label} ({_res.status}): {_res.notes}")
        if _notes:
            _note_text = "; ".join(_notes)
            if scope_ledger.notes:
                scope_ledger.notes += "; " + _note_text
            else:
                scope_ledger.notes = _note_text

    # Fold any malformed-opt-in-config disclosures (a CodeQL / BYO commercial
    # block that failed validation was ignored rather than crashing the scan).
    for _cfg_note in _lane_cfg_notes:
        if scope_ledger.notes:
            scope_ledger.notes += "; " + _cfg_note
        else:
            scope_ledger.notes = _cfg_note

    # Fold the DAST runtime-guard violation note (D-16-12 / SAFE-01). If any DAST
    # finding reached the merged set tagged evidence_type='runtime', it was
    # DROPPED above; record the SAFE-01 breach in the ledger so the disclosure is
    # honest. The scan still completed (never raised) — this is a tripwire note,
    # not a failure.
    if _dast_runtime_violations:
        _viol_note = (
            f"SAFE-01 violation: dropped {len(_dast_runtime_violations)} DAST "
            "finding(s) tagged evidence_type='runtime' (D-16-12 — DAST is never "
            "runtime; runtime is reserved for the Supabase two-account test)"
        )
        if scope_ledger.notes:
            scope_ledger.notes += "; " + _viol_note
        else:
            scope_ledger.notes = _viol_note

    # Phase 17 (Plan 17-03) — fold the verification-stage disclosures into the
    # scope ledger exactly like _dast_runtime_violations: (1) the Refuted appendix
    # summary (D-17-14 — how many findings the critic validly refuted; the full
    # auditable trail lives in meta.refuted_findings) and (2) any downgrade-only
    # post-pass violations (D-17-16 — a static->runtime smuggle that was reverted).
    _verif_notes: list = []
    if _refuted_findings:
        _verif_notes.append(
            f"Verification: {len(_refuted_findings)} finding(s) validly refuted "
            "and filed in the Refuted appendix (reason + citation in the JSON "
            "sidecar; never silently dropped — D-17-14)"
        )
    _downgrade_violations = _verification_meta.get("downgrade_violations", 0)
    if _downgrade_violations:
        _verif_notes.append(
            f"SAFE-01 violation: reverted {_downgrade_violations} finding(s) that "
            "gained evidence_type='runtime' they were not born with "
            "(downgrade-only post-pass — D-17-16)"
        )
    for _vn in _verif_notes:
        if scope_ledger.notes:
            scope_ledger.notes += "; " + _vn
        else:
            scope_ledger.notes = _vn

    # Plan 05-01 / TREND-01: baseline_run is conditional on a prior sidecar.
    # find_prior_sidecar returns the most-recent JSON sidecar with
    # meta.scan_date strictly before today (or None — same-day re-run, no
    # prior dir, no JSON, all-corrupt → baseline). The first real trend scan
    # flips baseline_run off (RESEARCH Pitfall 4 — was hard-coded True).
    # NOTE (Plan 15-05): prior_sidecar is ALREADY resolved ABOVE (before the
    # quality-depth step, for the per-scan regression bytes). We REUSE that same
    # variable here — no second find_prior_sidecar call.

    # Assemble ScanReport.
    meta = ReportMeta(
        repo_slug=slug,
        commit_sha=commit_sha,
        scan_date=scan_date,
        tool_version=__version__,
        detected_stacks=detection.stacks,
        baseline_run=(prior_sidecar is None),  # Plan 05-01: conditional (TREND-01)
        partial=partial,
        # Plan 07-05 (FND-02) SCA stamp EXTENDED with the Plan 10-04 SAST stamp
        # (D-10-02) — both feeds join the header; the SAST entry is present only
        # when the Semgrep run succeeded (build_sast_provenance returns [] on a
        # non-ok run, so a skipped/absent SAST contributes nothing here).
        feed_provenance=(
            list(sca_result.feed_provenance) + list(sast_result.feed_provenance)
        ),
    )

    # Phase 12 (Plan 12-05) / SUP-02 / D-12-07: stamp the SBOM REFERENCE path onto
    # the (mutable) ReportMeta. The SBOM document is NEVER inlined — only its
    # gitignored tool-repo path is carried. None when the SBOM step degraded
    # (Syft absent / no catalogable packages); the dimension degrades honestly.
    meta.sbom_path = (
        str(supply_chain_result.sbom_path)
        if supply_chain_result.sbom_path
        else None
    )

    # Phase 17 (Plan 17-03) / CRIT-5 + D-17-14: carry the verification-stage
    # disclosures onto the (mutable) ReportMeta. critic_reviewed (N) /
    # critic_total_queue (M) populate the "N of M critically reviewed" disclosure
    # (N < M on budget exhaustion); refuted_findings is the auditable Refuted
    # appendix (the AUTHORITATIVE JSON-sidecar trail). When the critic was skipped
    # (--no-agent → no_critic), critic_total_queue is 0 and refuted_findings is
    # the empty list (the deterministic corroboration still ran).
    meta.critic_reviewed = _verification_meta.get("critic_reviewed")
    meta.critic_total_queue = _verification_meta.get("critic_total_queue")
    meta.refuted_findings = list(_refuted_findings)
    # W1 (Plan 17-04) / T-17-04-04: carry the discarded-refutation COUNT onto the
    # (mutable) ReportMeta. There is NO generic verification_meta -> ReportMeta
    # carry — each field is copied INDIVIDUALLY (above), so this explicit
    # assignment is REQUIRED or the field stays None in all output. Makes a
    # fabricated/unresolvable critic citation provably visible to the auditor.
    meta.discarded_refutations = _verification_meta.get("discarded_refutations")

    # Plan 05-03 / TREND-02: compute the TrendDelta when a prior sidecar exists.
    # Parsed defensively — find_prior_sidecar already validated parseability, but
    # a race (file changed between selection and read) must not crash the scan.
    # The "current" side is a provisional ScanReport built from the findings +
    # meta + scope_ledger known at this point (the agent runs AFTER and only
    # narrates; it never alters the deterministic metrics the delta reads). The
    # TrendDelta is threaded into BOTH the agent session (so the agent can
    # narrate the deltas via trend_baseline) AND render_and_write (so the gate
    # folds the delta numbers into AllowedNumbers and the Trends section renders).
    # Plan 15-05: REUSE the prior_report parsed ABOVE (for the regression bytes) —
    # no second parse. A None prior_report (no sidecar, or a corrupt/raced prior
    # that failed the defensive parse above) → no trend, same as before.
    trend = None
    if prior_sidecar is not None and prior_report is not None:
        try:
            current_for_trend = ScanReport(
                schema_version="1",
                meta=meta,
                findings=findings,
                scope_ledger=scope_ledger,
            )
            trend = compute_trend(prior_report, current_for_trend, repo_path)
        except Exception:  # noqa: BLE001 — a corrupt/raced prior must not crash
            trend = None

    # Phase 4 NEW: AGENT-05 budget override (D-65) — one-shot scan override.
    # Mutates the AGENT_DEFAULTS dict the agent loop reads via get_threshold();
    # process-local + benign (each Typer invocation is a fresh CLI context).
    # UNCAPPED-01: --uncapped WINS over --agent-budget — when uncapped, SKIP the
    # mutation so the budget is ignored and AGENT_DEFAULTS stays pristine (the
    # cap is removed at runtime via the resolution helpers instead).
    if agent_budget is not None and not uncapped:
        from repo_audit.agent.constants import AGENT_DEFAULTS
        AGENT_DEFAULTS["agent.max_tokens_per_scan"] = int(agent_budget)

    # Phase 4 NEW: agent session (D-53, D-65, D-67, D-68).
    # Skipped under --no-agent for debugging the deterministic pipeline.
    # Returns (AgentScanReport | None, mutated_meta); on failure agent_output
    # is None and meta.agent_status carries the reason (D-67 exit-0 contract).
    # Called via the module attribute so the loop is patchable in tests and
    # session.py (which imports the SDK) is only pulled in when needed.
    agent_output = None
    if not no_agent:
        from repo_audit.agent import session as _agent_session
        agent_output, meta = asyncio.run(_agent_session.run_agent_session(
            findings=findings,
            scope_ledger=scope_ledger,
            detection=detection,
            meta=meta,
            uncapped=uncapped,
            trend=trend,
            top_findings=top_findings,
        ))
        # Plan 18-03 (D-69 / T-18-08): merge the agent's why_it_matters prose back
        # onto the Python-authored Top-N, matched by finding_ref. The Python
        # rank/score/ids stay AUTHORITATIVE — an agent that reorders or rescores is
        # ignored because only the prose field is read back from the emitted report.
        top_findings = _merge_why_it_matters(top_findings, agent_output)

    # Phase 4 NEW: AGENT-07 post-flight ledger-gap auto-fill (D-60).
    # Under D-57 read-only tools this is defense in depth — the agent path
    # cannot create gaps; this catches collector-execution bugs and primes
    # future action-tool semantics.
    findings, scope_ledger = auto_fill_ledger_gaps(
        findings, scope_ledger, detection,
        repo_path=repo_path,
        walker_index=walker_result.index,
    )

    scan_report = ScanReport(
        schema_version="1",
        meta=meta,
        findings=findings,
        scope_ledger=scope_ledger,
    )

    # Output paths (Pitfall 4 collision-safe per Plan 02-01a paths.py fix).
    md_path, json_path = state_report_paths(repo_path, scan_date)

    # Render + secret-lint + completion-honesty + faithfulness + write.
    # agent_output is None on --no-agent + every D-67 fallback → the renderer
    # takes the deterministic-only path (Plan 04-08).
    rc = render_and_write(
        scan_report, md_path, json_path, agent_output=agent_output, trend=trend,
        top_findings=top_findings, top_scores=top_scores,
    )
    # Overwrite wall_clock_seconds with the overall scan duration
    # (RESEARCH Open Question 2 — caller-overrides-session). This is the
    # user-facing total; session.py's agent-only measurement is superseded.
    # MUST happen AFTER render_and_write returns (RESEARCH Pitfall 5).
    meta.wall_clock_seconds = time.perf_counter() - overall_start
    if rc != 0:
        # render refused (secret-lint / completion-honesty); sidecar NOT
        # written. Caller raises typer.Exit(rc). No post-flight check needed
        # (nothing was written).
        return ScanResult(
            scan_report=scan_report,
            md_path=md_path,
            json_path=json_path,
            rc=rc,
            agent_status=meta.agent_status,
            offenders=[],
            prior_sidecar=prior_sidecar,
        )

    # D-33 post-flight integrity check (does NOT fail the scan).
    post_status = snapshot_git_status(repo_path)
    offenders = diff_git_status(pre_status, post_status)
    if offenders:
        # D-33 honesty contract: append integrity entry to in-memory
        # scope_ledger.notes so a follow-up tool inspection of the
        # ScanReport object surfaces the alert. The on-disk JSON sidecar
        # was already written before this check (the post-flight is a
        # tripwire for tool BUGS, not a routine ledger entry); future
        # Phase 5 can revisit if a "re-render with integrity row" gate
        # is wanted. The stderr INTEGRITY ALERT block is emitted by the
        # caller from ScanResult.offenders.
        integrity_note = (
            f"Integrity alert: {len(offenders)} unexpected "
            f"file(s) modified outside docs/state-reports/"
        )
        if scan_report.scope_ledger.notes:
            scan_report.scope_ledger.notes += "; " + integrity_note
        else:
            scan_report.scope_ledger.notes = integrity_note

    return ScanResult(
        scan_report=scan_report,
        md_path=md_path,
        json_path=json_path,
        rc=rc,
        agent_status=meta.agent_status,
        offenders=offenders,
        prior_sidecar=prior_sidecar,
    )
