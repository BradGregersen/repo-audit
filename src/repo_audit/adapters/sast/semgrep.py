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
    4. Gate on the exit code: semgrep succeeds with 0 (clean) or 1 (findings);
       any other exit (e.g. 7 for a missing registry pack) → unavailable. Then
       parse stdout as SARIF through the SINGLE parse path (FND-01);
       unparseable stdout → unavailable. A SARIF run carrying a
       ``toolExecutionNotifications`` entry at ``level: error`` →
       unavailable, because semgrep can exit cleanly after failing to load a
       rule pack.
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
from repo_audit.adapters.sca.refresh import _redact_tail
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

# Default wall-clock bound for a single Semgrep run over a repo (Pitfall 5 —
# tune on dogfood). run_tool does the SIGTERM→5s→SIGKILL escalation on expiry.
_SAST_TIMEOUT_SECONDS: float = 180.0

_SOURCE_TOOL = "semgrep"
_DIMENSION = "security"

# semgrep exit codes that mean the scan ran: 0 = clean, 1 = findings. Anything
# else (2 = fatal error, 7 = missing config, ...) is a failed run.
_SUCCESS_EXIT_CODES: frozenset[int] = frozenset({0, 1})

# Bound on the stderr tail carried into SastResult.notes (after whitespace is
# collapsed to one line).
_STDERR_TAIL_CHARS: int = 300


def _stderr_tail(text: str) -> str:
    """A bounded, single-line, secret-linted tail of a tool's stderr."""
    one_line = " ".join((text or "").split())
    return _redact_tail(one_line[-_STDERR_TAIL_CHARS:]) or "(no stderr)"


def _first_execution_error(sarif: object) -> Optional[str]:
    """Return the message of the first error-level execution notification.

    Walks ``runs[*].invocations[*].toolExecutionNotifications[*]`` defensively:
    any missing or non-dict level is skipped. Returns ``None`` when there is no
    error-level notification.
    """
    if not isinstance(sarif, dict):
        return None
    for run in sarif.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for invocation in run.get("invocations") or []:
            if not isinstance(invocation, dict):
                continue
            for note in invocation.get("toolExecutionNotifications") or []:
                if not isinstance(note, dict) or note.get("level") != "error":
                    continue
                message = note.get("message")
                text = message.get("text") if isinstance(message, dict) else None
                return text if isinstance(text, str) else ""
    return None


def _semgrep_argv(
    binary: Path,
    repo_path: Path,
    packs: list[str],
    excludes: tuple[str, ...],
    *,
    pro: bool = False,
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

    ``pro`` (BYO-02, Plan 16-06): when True, append ``--pro`` to engage the
    Semgrep Pro Engine (interfile/interprocedural taint). The Pro Engine
    requires a logged-in Pro entitlement (A9); an unentitled run errors, which
    the caller folds to ``status='unavailable'`` — it never crashes. Default
    ``pro=False`` preserves the existing 8-corpus CE behavior verbatim (the
    argv is byte-identical to before this parameter existed).
    """
    argv: list[str] = [str(binary), "scan", "--sarif", "--metrics", "off"]
    if pro:
        argv.append("--pro")
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
        semgrep is absent, exec-failed, exits outside {0, 1}, prints stdout
        that is not parseable SARIF, or reports an error-level execution
        notification;
        ``status='timeout'`` when the run exceeds ``timeout_seconds``. NEVER
        raises and NEVER hangs.
    """
    binary = resolve_tool(_SOURCE_TOOL, repo_path, trusted_only=True)
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

    # Gate on the exit code first: 0 (clean) and 1 (findings) are the only
    # success codes. Then stdout must parse as SARIF, and the SARIF must carry
    # no error-level execution notification (semgrep can exit cleanly after
    # failing to load a rule pack). Each failure is 'unavailable', never 'ok'.
    if invocation.returncode not in _SUCCESS_EXIT_CODES:
        return SastResult(
            status="unavailable",
            notes=(
                f"semgrep exited {invocation.returncode}, which is not a "
                f"success code; stderr: {_stderr_tail(invocation.stderr)}"
            ),
        )

    try:
        sarif = json.loads(invocation.stdout)
    except (json.JSONDecodeError, ValueError):
        return SastResult(
            status="unavailable",
            notes="semgrep produced no parseable SARIF",
        )

    execution_error = _first_execution_error(sarif)
    if execution_error is not None:
        return SastResult(
            status="unavailable",
            notes=(
                "semgrep reported an execution error: "
                + _stderr_tail(execution_error)
            ),
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
