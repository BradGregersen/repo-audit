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
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.mobile import run_mobile
from repo_audit.adapters.sast import run_sast
from repo_audit.adapters.sca import run_sca
from repo_audit.adapters.supabase import run_supabase
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
from repo_audit.trend.delta import compute_trend
from repo_audit.walker import build_repo_index


# SCAN-BOUND-01 (D-051-06) — per-scan wall-clock budget threaded into
# run_collectors as a deadline.
#
# 05.1-gap: lowered from 300 s and now ENFORCED INSIDE the read-heavy /
# subprocess collectors, not only between them. The Blocker-A bottleneck was
# secret_detection spawning a gitleaks subprocess PER text file: on the 40 GB
# adapt (~13.7 k text files) that never finished inside the 120 s acceptance
# canary. The between-collector check (the prior mechanism) could not interrupt
# it once running. Each read-heavy collector now polls THIS deadline from inside
# its own loop (and caps any subprocess timeout at the remaining budget), so the
# whole deterministic scan reliably finishes well under the canary while any
# truncated collector self-reports status!='ok' (-> partial banner + scope
# ledger disclosure, SAFE-08). 95 s is the COLLECTOR-phase budget: with the
# walker (~1 s), the stack adapters, and the render/secret-lint/write tail
# (~10-15 s on adapt) layered on top, the whole `repo-audit scan --no-agent` finishes
# comfortably under the 120 s acceptance canary while staying a tight tripwire
# (well below the documented 300 s ceiling). The per-file gitleaks subprocess is
# additionally capped at the budget remaining (see secret_detection.run), so the
# collector phase cannot overshoot this deadline by a full gitleaks timeout.
TIME_BUDGET_S: float = 95.0

# Self-reference so the cross-stack SCA step can be invoked via the module
# attribute (``scan_runner.run_sca``), keeping it monkeypatchable in tests the
# same way ``run_adapters`` is.
_THIS_MODULE = sys.modules[__name__]


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


def run_scan(
    repo_path: Path,
    *,
    no_agent: bool = False,
    refresh_coverage: bool = False,
    refresh_vuln_db: bool = False,
    agent_budget: int | None = None,
    rls_runtime: bool = False,
    rls_pgrls: bool = False,
    mobsf: bool = False,
    mobsf_build: bool = False,
    apk: Path | None = None,
    sast: bool = True,
    mutation: bool = False,
    typed_detekt: bool = True,
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
        9.5 agent_budget override (AGENT-05 / D-65)
        10. run_agent_session (unless no_agent) — D-53 / D-67
        10.5 auto_fill_ledger_gaps — AGENT-07 / D-60
        11. ScanReport assembly
        12. state_report_paths + render_and_write (D-07 / D-32)
        13. meta.wall_clock_seconds overwrite AFTER render (Pitfall 5)
        14. post-flight diff_git_status integrity tripwire (D-33 / Pitfall 7)

    Exit codes (carried on ScanResult.rc): 0 success / 2 secret-lint / 3
    completion-honesty.
    """
    repo_path = Path(repo_path).resolve()
    overall_start = time.perf_counter()  # Phase 4 — overall arch-scan wall-clock

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
    findings = (
        collector_adapter_prefix
        + list(sca_result.findings)
        + list(rls_result.findings)
        + list(mob_result.findings)
        + list(sast_result.findings)
        + list(kotlin_result.findings)
        + list(expo_result.findings)
        + list(test_depth_result.findings)
    )

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
    partial = (
        walker_result.status != "ok"
        or any(r.status != "ok" for r in collector_results)
        or any(r.status != "ok" for r in adapter_results)
        or sca_result.status != "ok"
        or rls_result.status != "ok"
        or mob_result.status != "ok"
        or sast_result.status != "ok"
        or kotlin_result.status != "ok"
        or expo_result.status != "ok"
        or test_depth_result.status != "ok"
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

    # Plan 05-01 / TREND-01: baseline_run is conditional on a prior sidecar.
    # find_prior_sidecar returns the most-recent JSON sidecar with
    # meta.scan_date strictly before today (or None — same-day re-run, no
    # prior dir, no JSON, all-corrupt → baseline). The first real trend scan
    # flips baseline_run off (RESEARCH Pitfall 4 — was hard-coded True).
    prior_sidecar = find_prior_sidecar(repo_path, scan_date)

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

    # Plan 05-03 / TREND-02: compute the TrendDelta when a prior sidecar exists.
    # Parsed defensively — find_prior_sidecar already validated parseability, but
    # a race (file changed between selection and read) must not crash the scan.
    # The "current" side is a provisional ScanReport built from the findings +
    # meta + scope_ledger known at this point (the agent runs AFTER and only
    # narrates; it never alters the deterministic metrics the delta reads). The
    # TrendDelta is threaded into BOTH the agent session (so the agent can
    # narrate the deltas via trend_baseline) AND render_and_write (so the gate
    # folds the delta numbers into AllowedNumbers and the Trends section renders).
    trend = None
    if prior_sidecar is not None:
        try:
            prior_report = ScanReport.model_validate_json(
                prior_sidecar.read_text(encoding="utf-8")
            )
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
    if agent_budget is not None:
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
            trend=trend,
        ))

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
    )
    # Phase 4: overwrite wall_clock_seconds with the overall arch-scan duration
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
