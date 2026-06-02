"""SAST-01 — Semgrep CE collector (Plan 10-03, Wave 3).

``collect_semgrep`` is the cross-stack SAST collection FUNCTION (NOT a per-stack
``@register_adapter`` entry — SAST is cross-stack, like ``adapters/sca`` +
``adapters/mobile``). Plan 10-04 wires it into ``orchestration/scan_runner`` as a
dedicated repo-wide scan step alongside ``run_sca`` / ``run_supabase`` /
``run_mobile``.

It mirrors ``sca/osv.py::collect_osv`` and ``mobile/mobsfscan.py``
verbatim in shape — a thin, never-raising collector that resolves the binary,
invokes it through the single shared ``run_tool`` seam (FND-04), parses its
SARIF through the single ``sarif_to_findings`` path (FND-01), applies the Plan
10-02 deterministic transforms in order, and returns a ``SastResult`` envelope.

The pipeline:

    1. resolve_tool("semgrep", repo) — vendor → node_modules → PATH (D-06-10).
       None → status='unavailable' (no semgrep, nothing to scan).
    2. run_tool([binary, "scan", "--sarif", "--metrics", "off",
       "--config" p/... (one per pack), "--exclude" pat (pre-filter speed),
       repo]) — under an env carrying SEMGREP_ENABLE_VERSION_CHECK=0 +
       SEMGREP_SEND_METRICS=off. NEVER ``--config auto`` (no login/telemetry
       egress — Pitfall 3, T-10-03-03).
    3. Gate on the run_tool sentinels: TIMED_OUT (-2) → status='timeout';
       EXEC_FAILED (-1) → status='unavailable'.
    4. Parse stdout as SARIF through the SINGLE parse path (FND-01). Semgrep
       exits 0 EVEN WITH findings, so we gate on whether stdout PARSES, not on
       returncode (Pitfall 6, T-10-03-04). Unparseable stdout → unavailable.
    5. apply_noise_floor (SAST-02) → drop_anon_key_secrets (SAST-03) →
       annotate_owasp (OWASP/CWE tags) — in that order.
    6. Extract scanner_version from the SARIF driver (FeedProvenance, Plan 04).

``collect_semgrep`` NEVER raises across its boundary and NEVER hangs: every
failure mode (absent binary, exec failure, timeout, unparseable SARIF, a parse
exception) folds into a ``SastResult`` status. ``run_tool``'s SIGTERM→5s→SIGKILL
escalation backs the no-hang guarantee even against an offline registry fetch
(T-10-03-02).

NOTE: ``resolve_tool`` is imported as a module-level name so the Wave-0 test can
``monkeypatch.setattr(semgrep, "resolve_tool", ...)`` the absent-binary path.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sast import SastResult
from repo_audit.adapters.sast.anon import drop_anon_key_secrets
from repo_audit.adapters.sast.noise import DEFAULT_EXCLUDES, apply_noise_floor
from repo_audit.adapters.sast.owasp import annotate_owasp
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

# Default wall-clock bound for a single Semgrep run over a repo (Pitfall 5 —
# tune on dogfood). run_tool does the SIGTERM→5s→SIGKILL escalation on expiry.
_SAST_TIMEOUT_SECONDS: float = 180.0

_SOURCE_TOOL = "semgrep"
_DIMENSION = "security"


def _semgrep_argv(
    binary: Path,
    repo_path: Path,
    packs: list[str],
    excludes: tuple[str, ...],
) -> list[str]:
    """Build the EXACT Semgrep ``scan`` argv (list[str], shell=False guard).

    ``--sarif`` selects the single SARIF output path (FND-01). ``--metrics off``
    suppresses telemetry egress (Pitfall 3, T-10-03-03). One ``--config p/...``
    per selected pack — these are OUR OWN constants (``rulesets.select_packs``),
    never target-supplied (T-10-03-01). The argv NEVER passes a bare
    ``--config auto`` config target (which would trigger a login/registry
    handshake) — only explicit ``p/...`` registry packs are configured. The
    ``--exclude`` pre-filter mirrors the noise floor's default excludes so
    Semgrep skips vendored/test trees up front (speed); the noise floor still
    drops them post-parse as the authoritative gate. ``repo_path`` is a single
    argv element — never interpolated into a shell string.
    """
    argv: list[str] = [str(binary), "scan", "--sarif", "--metrics", "off"]
    for pack in packs:
        argv += ["--config", pack]
    for pat in excludes:
        argv += ["--exclude", pat]
    argv.append(str(repo_path))
    return argv


def _sast_env(env: dict[str, str]) -> dict[str, str]:
    """Layer the no-egress Semgrep env vars onto the caller's scan env.

    ``SEMGREP_ENABLE_VERSION_CHECK=0`` suppresses the startup version-check HTTP
    call; ``SEMGREP_SEND_METRICS=off`` belt-and-braces the ``--metrics off``
    flag. Together with the absence of ``--config auto`` this is the
    T-10-03-03 information-disclosure mitigation — no telemetry, no login.
    """
    e = dict(env)
    e["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    e["SEMGREP_SEND_METRICS"] = "off"
    return e


def _driver_version(sarif: dict) -> Optional[str]:
    """Pull ``runs[0].tool.driver.version`` from the Semgrep SARIF, guarding gaps.

    Mirrors ``osv._extract_scanner_version``. Returns ``None`` on any structural
    gap (no runs, no driver, non-string version).
    """
    try:
        runs = sarif.get("runs") or []
        driver = ((runs[0] or {}).get("tool") or {}).get("driver") or {}
        version = driver.get("version")
        return version if isinstance(version, str) else None
    except (IndexError, AttributeError, TypeError):
        return None


def collect_semgrep(
    repo_path: Path,
    env: dict[str, str],
    *,
    packs: list[str],
    timeout_seconds: float = _SAST_TIMEOUT_SECONDS,
) -> SastResult:
    """Run Semgrep over ``repo_path`` with ``packs`` and return de-noised findings.

    Args:
        repo_path: the repo to scan (Semgrep scans recursively from here).
        env: the child environment (cache-redirected by the caller, Plan 04).
            The no-egress Semgrep vars are layered on top via :func:`_sast_env`.
        packs: the ``p/...`` registry packs to apply (one ``--config`` each).
            Resolved by ``rulesets.select_packs`` and passed in by the Plan 04
            wiring — they are OUR constants, never target-supplied.
        timeout_seconds: hard wall-clock bound for the run (default 180s).

    Returns:
        A :class:`SastResult`. ``status='ok'`` with security-dimension
        static/candidate findings on success; ``status='unavailable'`` when
        semgrep is absent, exec-failed, or stdout is not parseable SARIF;
        ``status='timeout'`` when the run exceeds ``timeout_seconds``. NEVER
        raises and NEVER hangs.
    """
    binary = resolve_tool(_SOURCE_TOOL, repo_path)
    if binary is None:
        return SastResult(
            status="unavailable",
            notes="semgrep not found (vendor + node_modules + PATH miss)",
        )

    invocation = run_tool(
        _semgrep_argv(binary, repo_path, packs, DEFAULT_EXCLUDES),
        env=_sast_env(env),
        cwd=repo_path,
        timeout_seconds=timeout_seconds,
    )

    # Map the run_tool structural sentinels first — these NEVER raise.
    if invocation.returncode == TIMED_OUT:
        return SastResult(
            status="timeout",
            notes=f"semgrep exceeded {timeout_seconds:.0f}s",
        )
    if invocation.returncode == EXEC_FAILED:
        return SastResult(
            status="unavailable",
            notes=f"semgrep could not be executed: {invocation.stderr}",
        )

    # Gate on whether stdout PARSES as SARIF, NOT on returncode: Semgrep exits 0
    # even with findings present, so a non-zero exit is a tool problem rather
    # than a "found issues" signal, and an unparseable stdout is unavailable
    # (Pitfall 6, T-10-03-04).
    try:
        sarif = json.loads(invocation.stdout)
    except (json.JSONDecodeError, ValueError):
        return SastResult(
            status="unavailable",
            notes="semgrep produced no parseable SARIF",
        )

    # SARIF is the SINGLE finding source (FND-01). The empty severity_map selects
    # the parser's faithful default level map (with the Wave-1
    # defaultConfiguration.level fallback); the parser stamps
    # evidence_type='static' + confidence='candidate' and enforces the SCH-04
    # candidate cap.
    try:
        findings = sarif_to_findings(
            sarif,
            source_tool=_SOURCE_TOOL,
            default_dimension=_DIMENSION,
            severity_map={},
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return SastResult(
            status="unavailable",
            notes=f"semgrep SARIF parse failed: {type(exc).__name__}: {exc}",
        )

    # Plan 10-02 deterministic transforms, IN ORDER:
    #   1. noise floor (SAST-02) — drop test/mock/generated/vendored paths +
    #      sub-floor severities BEFORE any finding reaches the report (CRIT-2).
    #   2. anon-key drop (SAST-03) — drop the public-anon-key FP, redact + RLS
    #      cross-link the genuine secrets.
    #   3. OWASP/CWE enrichment — fold the rule tags onto parsed_value
    #      (count-invariant; SARIF stays the single finding source).
    findings = apply_noise_floor(findings)
    findings = drop_anon_key_secrets(findings)
    findings = annotate_owasp(findings, sarif)

    return SastResult(
        findings=findings,
        status="ok",
        scanner_version=_driver_version(sarif),
        notes=f"semgrep: {len(findings)} finding(s)",
    )


def run_semgrep(
    repo_path: Path,
    *,
    packs: list[str],
    timeout_seconds: float = _SAST_TIMEOUT_SECONDS,
) -> SastResult:
    """Convenience wrapper: run :func:`collect_semgrep` with a default scan env.

    Builds a per-call cache-redirected scan env (mirrors ``run_mobsfscan`` and
    how the SCA step seeds ``build_scan_env``) so callers/tests that don't
    already have an env can invoke the collector directly — the ``-m
    integration`` live test uses this path. Plan 04 calls ``collect_semgrep``
    with the shared scan env instead.
    """
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        return collect_semgrep(
            repo_path, env, packs=packs, timeout_seconds=timeout_seconds
        )


__all__ = ["collect_semgrep", "run_semgrep", "resolve_tool"]
