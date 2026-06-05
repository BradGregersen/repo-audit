"""CodeQL opt-in lane (DSAST-01, Plan 16-04): gate -> db create -> analyze -> SARIF.

``run_codeql`` is the live-invocation lane for CodeQL taint/dataflow as an
OPT-IN adapter (default OFF). It slots into the SAME shape ``byo/adapter.py``
reserved for Phase 16 — gate FIRST, then the live invocation, then the SHARED
``sarif_to_findings`` read+parse (no fork) — and copies the
``sast/semgrep.py`` resolve -> run_tool -> sentinel ladder for the live step.

Posture (the load-bearing guarantees)
-------------------------------------
* **Default OFF (D-16-08 / T-16-04-01):** without ``cfg.should_run`` (enabled
  AND use_rights_attestation AND a use_rights ground) the lane returns
  ``unavailable`` and invokes NOTHING — no subprocess, the SARIF is never even
  opened. The standard build stays license-clean.
* **Auditable ground:** on a successful run the chosen ``use_rights`` ground is
  stamped into provenance (``build_codeql_provenance``) — "under which right was
  CodeQL run?" is answerable, not merely gated.
* **Interpreted-only (Pitfall 5 / A3):** CodeQL ``database create`` needs no
  build only for interpreted langs (JS/TS -> ``javascript``, Python ->
  ``python``). A compiled-lang-only repo degrades to honest ``unavailable`` —
  this tool never runs a build to create a DB.
* **Shared SARIF (06-01 candidate cap):** the analyze SARIF routes through the
  ONE ``sarif_to_findings`` path every OSS/BYO tool uses, so a CodeQL
  error-level result surfaces as ``severity='major' + confidence='candidate'``,
  never candidate+critical.
* **PATH-hijack (CR-01 / T-16-04-02):** ``resolve_tool('codeql', repo,
  trusted_only=True)`` — a ``codeql`` planted in the target repo's
  ``node_modules/.bin`` is NEVER executed (CodeQL is a security scanner).
* **Read-only (T-16-04-04):** the DB dir + SARIF output land under the
  caller-provided ``scratch_dir`` (a ``scan_tempdir`` wired in Plan 16-07),
  NEVER the read-only target repo.
* **No-hang / never-raise (D-25 / T-16-04-05):** ``run_tool``'s long
  ``timeout_seconds`` cap + SIGTERM->5s->SIGKILL escalation; TIMED_OUT ->
  timeout; EXEC_FAILED / resolve None / missing-or-unparseable SARIF ->
  unavailable. Every failure folds into a status; the lane never raises.

NOTE: ``resolve_tool`` and ``run_tool`` are module-level names so tests can
``monkeypatch.setattr(codeql, "run_tool", ...)`` the live step.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.codeql.config import CodeQlConfig
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif import sarif_to_findings
from repo_audit.adapters.sast.provenance import build_codeql_provenance
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

if TYPE_CHECKING:
    from repo_audit.schema.detection import DetectionResult

_SOURCE_ADAPTER = "codeql"
_SOURCE_TOOL = "codeql"
_DEFAULT_DIMENSION = "security"

# Interpreted-stack -> CodeQL `--language` value. CodeQL `database create` needs
# NO build for these (Pitfall 5). A detected stack outside this map is treated as
# compiled-lang (needs a build) and the lane degrades to unavailable.
_INTERPRETED_LANGUAGE: dict[str, str] = {
    "typescript-node": "javascript",
    "react-native": "javascript",
    "expo": "javascript",
    "python": "python",
}


def _unavailable(notes: str, dimension: str) -> AdapterResult:
    """Build the honest unavailable result (no findings)."""
    return AdapterResult(
        status="unavailable",
        notes=notes,
        source_adapter=_SOURCE_ADAPTER,
        source_tool=_SOURCE_TOOL,
        dimension=dimension,
    )


def _timeout(notes: str, dimension: str) -> AdapterResult:
    """Build the honest timeout result (no findings)."""
    return AdapterResult(
        status="timeout",
        notes=notes,
        source_adapter=_SOURCE_ADAPTER,
        source_tool=_SOURCE_TOOL,
        dimension=dimension,
    )


def _pick_language(detection: "DetectionResult") -> Optional[str]:
    """Return the CodeQL `--language` for the first interpreted stack, else None.

    None means the repo has no interpreted stack CodeQL can DB-create without a
    build — the caller degrades to the Pitfall-5 unavailable note.
    """
    for profile in detection.stacks:
        lang = _INTERPRETED_LANGUAGE.get(profile.stack)
        if lang is not None:
            return lang
    return None


def run_codeql(
    repo_path: str | Path,
    *,
    base_env: dict[str, str],
    cfg: Optional[CodeQlConfig],
    scratch_dir: str | Path,
    detection: "DetectionResult",
) -> AdapterResult:
    """Run the CodeQL opt-in lane: gate -> db create -> analyze -> shared SARIF.

    Args:
        repo_path: the read-only scan root (CodeQL's ``--source-root``).
        base_env: the cache-redirected child env (wired by the caller).
        cfg: the validated :class:`CodeQlConfig` (the use-rights gate), or
            ``None`` when the ``codeql:`` block is absent (lane stays absent).
        scratch_dir: a caller-provided tempdir (a ``scan_tempdir``); the DB dir
            and SARIF output land HERE, never the read-only repo.
        detection: the stack-detection result; the interpreted language is read
            from ``detection.stacks[].stack``.

    Returns:
        An :class:`AdapterResult`. ``status='ok'`` with ``source_tool='codeql'``
        candidate findings on success; ``status='timeout'`` on a hung run;
        ``status='unavailable'`` for default-OFF, compiled-lang-only, absent
        binary, exec failure, or a missing/unparseable SARIF. NEVER raises.
    """
    dimension = cfg.default_dimension if cfg is not None else _DEFAULT_DIMENSION

    # 1. Gate FIRST (D-16-08): default-OFF -> NO subprocess, SARIF never opened.
    if cfg is None or not cfg.should_run:
        return _unavailable(
            "CodeQL not enabled, not attested, or no use_rights ground — "
            "skipped (default OFF, D-16-08).",
            dimension,
        )

    # 2. Scope to interpreted langs (Pitfall 5 / A3): compiled-lang-only -> honest
    #    unavailable. CodeQL DB-create for a compiled language needs a build
    #    command, which this read-only tool will not run.
    language = _pick_language(detection)
    if language is None:
        stacks = ", ".join(p.stack for p in detection.stacks) or "none"
        return _unavailable(
            f"CodeQL DB build needs a build command for {stacks}; not attempted "
            "(interpreted-only scope, Pitfall 5).",
            dimension,
        )

    # 3. Resolve the binary trusted-only (CR-01): a target-repo node_modules
    #    codeql is NEVER executed. Absent binary -> unavailable.
    binary = resolve_tool(_SOURCE_TOOL, Path(repo_path), trusted_only=True)
    if binary is None:
        return _unavailable(
            "codeql not found (vendor + system PATH miss; trusted-only).",
            dimension,
        )

    # 4. All scratch lands under scratch_dir, NEVER the read-only repo (T-16-04-04).
    scratch = Path(scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    db_dir = scratch / "codeql-db"
    sarif_path = scratch / "codeql.sarif"

    create = run_tool(
        [
            str(binary),
            "database",
            "create",
            str(db_dir),
            f"--language={language}",
            "--source-root",
            str(repo_path),
        ],
        env=base_env,
        cwd=str(scratch),
        timeout_seconds=cfg.timeout_seconds,
    )
    if create.returncode == TIMED_OUT:
        return _timeout("codeql database create timed out", dimension)
    if create.returncode == EXEC_FAILED:
        return _unavailable(
            f"codeql database create could not be executed: {create.stderr}",
            dimension,
        )

    analyze = run_tool(
        [
            str(binary),
            "database",
            "analyze",
            str(db_dir),
            f"{language}-security-and-quality.qls",
            "--format=sarif-latest",
            "--output",
            str(sarif_path),
        ],
        env=base_env,
        cwd=str(scratch),
        timeout_seconds=cfg.timeout_seconds,
    )
    if analyze.returncode == TIMED_OUT:
        return _timeout("codeql database analyze timed out", dimension)
    if analyze.returncode == EXEC_FAILED:
        return _unavailable(
            f"codeql database analyze could not be executed: {analyze.stderr}",
            dimension,
        )

    # 5. Read + route through the SHARED parser (no fork). A missing/unparseable
    #    SARIF folds into unavailable — never a crash (D-25).
    try:
        with sarif_path.open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return _unavailable(
            "codeql produced no SARIF output (analyze wrote nothing).", dimension
        )
    except (OSError, json.JSONDecodeError) as exc:
        return _unavailable(
            f"codeql SARIF unreadable: {type(exc).__name__}: {exc}", dimension
        )

    if not isinstance(doc, dict):
        return _unavailable(
            f"codeql SARIF did not load as a mapping (got {type(doc).__name__}).",
            dimension,
        )

    try:
        findings = sarif_to_findings(
            doc,
            source_tool=_SOURCE_TOOL,
            default_dimension=cfg.default_dimension,
            severity_map=cfg.severity_map,  # type: ignore[arg-type]
        )
    except Exception as exc:  # noqa: BLE001 — D-25 boundary: never raise
        return _unavailable(
            f"codeql SARIF parse failed: {type(exc).__name__}: {exc}", dimension
        )

    # Stamp the chosen use_rights ground into provenance on success (D-16-08).
    provenance = build_codeql_provenance(status="ok", use_rights=cfg.use_rights)
    note = provenance[0].note if provenance else f"codeql: {len(findings)} finding(s)"

    return AdapterResult(
        findings=findings,
        status="ok",
        notes=note,
        source_adapter=_SOURCE_ADAPTER,
        source_tool=_SOURCE_TOOL,
        dimension=cfg.default_dimension,
    )


__all__ = ["run_codeql"]
