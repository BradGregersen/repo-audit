"""DAST lane (DAST-01) — opt-in ZAP baseline (passive) scan.

The lane whose entire reason to exist is the no-inference guarantee (SC4 /
Pitfall 7): the ZAP target enters the ``-t`` argv from EXACTLY ONE source,
``cfg.target_url`` (read from ``.repo-audit.yaml`` at call time). No CLI
flag, no default, no repo-derivation. No configured target → the lane refuses
(``status='unavailable'``) without ever invoking a subprocess.

:func:`run_dast` flow:

  1. SCOPE GUARD — ``not opt_in or not cfg.target_url`` → ``unavailable`` (NO
     subprocess; the function is structurally incapable of scanning a host it
     was not explicitly handed, T-16-05-01).
  2. INVOKE — build the ZAP baseline argv with ``cfg.target_url`` as the ONLY
     value reaching ``-t``; output JSON lands under ``scratch_dir`` (NEVER the
     repo, T-16-05-03). Baseline/passive ONLY, unauthenticated (D-16-11,
     T-16-05-05).
  3. SENTINELS — ``run_tool`` ``TIMED_OUT`` → timeout; ``EXEC_FAILED`` →
     unavailable. Gate on whether the JSON PARSES, not the exit code (ZAP exits
     non-zero on findings, Pitfall 9).
  4. NORMALIZE — ``zap_json_to_findings`` @ ``evidence_type='heuristic'``.
  5. POST-PASS GUARD (D-16-12, SAFE-01 downgrade-only) — drop any finding tagged
     ``evidence_type='runtime'`` and fold to ``status='partial'``, recording the
     invariant violation. This NEVER raises across the adapter boundary (D-25):
     a bare ``assert all(...)`` would propagate an AssertionError through
     ``run_dast`` → ``scan_runner.run_scan`` and crash the scan — forbidden.

The whole function NEVER raises and NEVER hangs (D-25 / SAFE-08).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.dast.config import DastConfig, read_dast_config
from repo_audit.adapters.dast.zap_json import zap_json_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

_SOURCE_TOOL = "zap"
_DIMENSION = "security"
_OUT_JSON_NAME = "out.json"
# The evidence type this lane is FORBIDDEN from emitting (D-16-12 / SAFE-01).
# A finding carrying this tag is dropped by the post-pass guard and folds the
# result to partial — runtime is reserved for the Phase-8 Supabase test only.
_FORBIDDEN_EVIDENCE_TYPE = "runtime"

DastStatus = Literal["ok", "partial", "unavailable", "timeout"]


@dataclass
class DastResult:
    """The never-raise envelope returned by :func:`run_dast`.

    Mirrors ``test_depth.TestDepthScanResult`` so the Plan-16-07 scan-runner step
    folds it the same way: read ``findings`` into the merged set, OR
    ``status != 'ok'`` into the partial flag, fold ``notes`` / ``ledger_notes``
    into the scope ledger.
    """

    # Tell pytest NOT to collect this dataclass as a test class.
    __test__ = False

    findings: list[Finding] = field(default_factory=list)
    status: DastStatus = "ok"
    source_tool: str = _SOURCE_TOOL
    dimension: str = _DIMENSION
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


def _drop_runtime_findings(
    findings: list[Finding],
) -> tuple[list[Finding], list[str]]:
    """POST-PASS GUARD (D-16-12 / SAFE-01 downgrade-only, never raises).

    Drop any finding whose ``evidence_type`` is the forbidden ``runtime`` tag and
    report the violation. The invariant ("no finding from this lane is runtime")
    is expressed as an ``assert`` but WRAPPED so an AssertionError can NEVER
    escape ``run_dast`` → ``scan_runner.run_scan`` (D-25 never-raise contract);
    on violation we fold to a disclosed downgrade rather than crashing the scan.

    Returns ``(kept_findings, violation_notes)``. When ``violation_notes`` is
    non-empty the caller degrades ``status`` to ``'partial'``.
    """
    kept: list[Finding] = []
    dropped = 0
    for f in findings:
        if f.evidence_type == _FORBIDDEN_EVIDENCE_TYPE:
            dropped += 1
            continue
        kept.append(f)

    violation_notes: list[str] = []
    try:
        # The structural invariant: this lane only ever produces heuristic
        # findings. If it somehow tagged one runtime, that is a SAFE-01 breach.
        assert dropped == 0, (
            f"DAST emitted {dropped} finding(s) tagged "
            f"{_FORBIDDEN_EVIDENCE_TYPE!r} — dropped (SAFE-01 downgrade-only)"
        )
    except AssertionError as exc:  # fold to partial; MUST NOT escape (D-25)
        violation_notes.append(str(exc))

    return kept, violation_notes


def run_dast(
    repo_path: str | Path,
    cfg: DastConfig | None = None,
    *,
    base_env: dict[str, str] | None = None,
    opt_in: bool = False,
    scratch_dir: str | Path | None = None,
) -> DastResult:
    """Run the opt-in ZAP baseline lane (DAST-01). NEVER raises, NEVER hangs.

    Args:
        repo_path: target repository root (used only to read the per-repo
            ``dast:`` config when ``cfg`` is not supplied — NEVER to derive a
            target).
        cfg: a pre-resolved :class:`DastConfig`; read from ``repo_path`` when
            omitted.
        base_env: child env for the ZAP subprocess (defaults to an empty env).
        opt_in: the lane runs ONLY when both this is True AND
            ``cfg.target_url`` is set — providing the URL IS the opt-in
            (D-16-10).
        scratch_dir: caller-owned scratch directory the ZAP ``-J`` output lands
            in (bind-mounted to ``/zap/wrk``). NEVER the target repo
            (T-16-05-03). When omitted, the lane refuses (no safe place to
            write).

    Returns:
        A :class:`DastResult`. ``unavailable`` when no target is configured (no
        subprocess), ``timeout`` / ``unavailable`` on the run_tool sentinels,
        ``ok`` / ``partial`` otherwise. NEVER raises (D-25).
    """
    cfg = cfg or read_dast_config(Path(repo_path))

    # --- 1. SCOPE GUARD: no opt-in / no configured target → refuse ------------
    # cfg.target_url is the ONLY assignment in this module that can reach the ZAP
    # -t argv. Absent it, the lane NEVER invokes a subprocess.
    if not opt_in or not cfg.target_url:
        return DastResult(
            status="unavailable",
            notes=(
                "DAST not run: no dast.target_url configured "
                "(config-only target, D-16-10)"
            ),
            ledger_notes=[
                "DAST unavailable: no dast.target_url configured "
                "(the lane refuses to derive a target, SC4)"
            ],
        )

    # No scratch dir → no read-only-safe place to land ZAP output → refuse
    # rather than write into the target repo (T-16-05-03).
    if scratch_dir is None:
        return DastResult(
            status="unavailable",
            notes="DAST not run: no scratch_dir supplied (output must not land in the repo)",
            ledger_notes=["DAST unavailable: no scratch_dir for ZAP output"],
        )

    scratch = Path(scratch_dir)
    out_json = scratch / _OUT_JSON_NAME
    env = base_env if base_env is not None else {}

    # --- 2. INVOKE: cfg.target_url is the SINGLE -t source --------------------
    # Baseline/passive mode ONLY (no active-attack flag), unauthenticated this
    # phase (D-16-11). There is NO other expression in this module that supplies
    # the -t value (grep-asserted single source, SC4).
    argv = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{scratch}:/zap/wrk:rw",
        "zaproxy/zap-stable",
        "zap-baseline.py",
        "-t",
        cfg.target_url,
        "-J",
        _OUT_JSON_NAME,
    ]

    invocation = run_tool(
        argv,
        env=env,
        cwd=scratch,
        timeout_seconds=cfg.timeout_seconds,
    )

    # --- 3. SENTINELS (these NEVER raise) -------------------------------------
    if invocation.returncode == TIMED_OUT:
        return DastResult(
            status="timeout",
            notes=f"ZAP baseline exceeded {cfg.timeout_seconds:.0f}s",
            ledger_notes=["DAST timeout: ZAP baseline wall-clock cap exceeded"],
        )
    if invocation.returncode == EXEC_FAILED:
        return DastResult(
            status="unavailable",
            notes=f"ZAP baseline could not be executed: {invocation.stderr}",
            ledger_notes=["DAST unavailable: docker/ZAP could not be executed"],
        )

    # --- 4. NORMALIZE: gate on whether out.json PARSES, not the exit code -----
    # ZAP exits non-zero when it finds alerts (Pitfall 9) — a non-zero exit is
    # NOT a failure signal. A missing / unparseable out.json IS unavailable.
    try:
        doc = json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return DastResult(
            status="unavailable",
            notes=f"ZAP baseline produced no parseable JSON: {type(exc).__name__}",
            ledger_notes=["DAST unavailable: ZAP -J output missing or unparseable"],
        )

    findings = zap_json_to_findings(doc)

    # --- 5. POST-PASS GUARD: drop any runtime-tagged finding, fold to partial -
    findings, violation_notes = _drop_runtime_findings(findings)

    status: DastStatus = "ok"
    ledger_notes: list[str] = []
    if violation_notes:
        status = "partial"
        ledger_notes.extend(violation_notes)

    return DastResult(
        findings=findings,
        status=status,
        source_tool=_SOURCE_TOOL,
        dimension=_DIMENSION,
        notes=f"ZAP baseline: {len(findings)} finding(s)",
        ledger_notes=ledger_notes,
    )


__all__ = [
    "DastConfig",
    "DastResult",
    "DastStatus",
    "read_dast_config",
    "run_dast",
    "zap_json_to_findings",
]
