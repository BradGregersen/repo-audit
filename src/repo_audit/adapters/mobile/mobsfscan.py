"""MOB-01 (9-T1) — Tier-1 mobsfscan SARIF collector (Plan 09-01, Wave 1).

``collect_mobsfscan`` is the no-build default mobile collector: it invokes
``mobsfscan --sarif --no-fail --type android <native_root>`` through the single
shared ``run_tool`` seam (FND-04), parses the SARIF from stdout through the
single ``sarif_to_findings`` path (FND-01), and returns an ``AdapterResult``.
No Docker, no APK, no working-tree mutation — mobsfscan reads the native Android
source (Java/Kotlin/XML) for bundled secrets, insecure storage, and weak crypto.

It does NOT cover JS/TS (verified live) — that is Plan 02's job.

Design constraints mirrored from the Phase-7 osv-scanner adapter:

    * Subprocess only through ``run_tool`` — never ``subprocess`` directly. The
      list[str] argv + shell=False is the structural injection guard (T-09-02);
      ``native_root`` is a single argv element, never interpolated into a shell
      string.
    * ``--no-fail`` forces mobsfscan to exit 0 even when it finds issues (A5), so
      a non-zero exit unambiguously means "tool problem", not "findings present".
    * Explicit ``timeout_seconds`` (default 180s) → ``run_tool`` does the
      SIGTERM→5s→SIGKILL escalation and returns the ``TIMED_OUT`` sentinel; this
      collector maps that to ``status='timeout'`` and never hangs (T-09-06).
    * SARIF is the SINGLE finding source: ``sarif_to_findings`` is the only
      producer of Finding objects here (it already stamps
      ``evidence_type='static'``, ``confidence='candidate'`` and applies the
      SCH-04 cap — no candidate+critical/blocker).
    * Never raises across its boundary: a top-level try/except backstop folds
      any unexpected exception into ``status='unavailable'`` (base.py contract).

NOTE: registration (``@register_adapter("mobile")`` / ``run_mobile``) is owned by
Plan 05 — this module deliberately does NOT register, to avoid a half-wired
adapter. ``run_mobsfscan`` is a thin convenience wrapper (default cache-redirected
env) so the live integration test can invoke the collector without plumbing.
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.sarif.parser import (
    sarif_to_findings as _sarif_to_findings,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

# Default wall-clock bound for a single mobsfscan run over a native source tree.
_MOBSFSCAN_TIMEOUT_SECONDS: float = 180.0

# The dimension every mobsfscan finding lands in (native security surface).
_DIMENSION = "security"
_SOURCE_TOOL = "mobsfscan"
_SOURCE_ADAPTER = "mobile"


def _argv(native_root: Path) -> list[str]:
    """Build the EXACT mobsfscan Tier-1 argv.

    ``--no-fail`` (A5) forces exit 0 on findings so ``unavailable`` (tool
    problem) stays distinguishable from "found issues". ``--type android``
    scopes the scan to the native Android ruleset. ``native_root`` is a single
    argv element — never interpolated into a shell string (T-09-02).
    """
    return [
        "mobsfscan",
        "--sarif",
        "--no-fail",
        "--type",
        "android",
        str(native_root),
    ]


def collect_mobsfscan(
    native_root: Path,
    *,
    env: dict[str, str],
    timeout_seconds: float = _MOBSFSCAN_TIMEOUT_SECONDS,
) -> AdapterResult:
    """Run mobsfscan over ``native_root`` and return its findings.

    Args:
        native_root: the native Android source root (the dir containing
            ``android/`` or ``android/`` itself — the caller, Plan 05, resolves
            which). Passed as a single argv element to ``run_tool``.
        env: the child environment (cache-redirected by the caller). Passed
            verbatim to ``run_tool``.
        timeout_seconds: hard wall-clock bound for the run (default 180s).

    Returns:
        An :class:`AdapterResult`. ``status='ok'`` with security-dimension
        candidate findings on success; ``status='unavailable'`` when mobsfscan
        is absent, the native source is missing, or stdout is not parseable
        SARIF; ``status='timeout'`` when the run exceeds ``timeout_seconds``.
        NEVER raises and NEVER hangs.
    """
    try:
        native_root = Path(native_root)

        # No native source → honest unavailable (nothing to scan).
        if not native_root.exists():
            return AdapterResult(
                status="unavailable",
                source_adapter=_SOURCE_ADAPTER,
                source_tool=_SOURCE_TOOL,
                dimension=_DIMENSION,
                notes="no native android source at "
                f"{native_root}",
            )

        invocation = run_tool(
            _argv(native_root),
            env=env,
            cwd=native_root,
            timeout_seconds=timeout_seconds,
        )

        # Map the run_tool sentinels — these NEVER raise.
        if invocation.returncode == EXEC_FAILED:
            return AdapterResult(
                status="unavailable",
                source_adapter=_SOURCE_ADAPTER,
                source_tool=_SOURCE_TOOL,
                dimension=_DIMENSION,
                notes="mobsfscan not found on PATH",
            )
        if invocation.returncode == TIMED_OUT:
            return AdapterResult(
                status="timeout",
                source_adapter=_SOURCE_ADAPTER,
                source_tool=_SOURCE_TOOL,
                dimension=_DIMENSION,
                notes=(
                    "mobsfscan exceeded "
                    f"{timeout_seconds:.0f}s"
                ),
            )

        # Real exit code — parse stdout as SARIF. Malformed/empty → unavailable.
        try:
            sarif = json.loads(invocation.stdout)
        except (json.JSONDecodeError, ValueError):
            return AdapterResult(
                status="unavailable",
                source_adapter=_SOURCE_ADAPTER,
                source_tool=_SOURCE_TOOL,
                dimension=_DIMENSION,
                notes="mobsfscan produced no parseable SARIF",
            )

        # SARIF is the SINGLE finding source (FND-01). The empty severity_map
        # selects the parser's faithful default level map (error→critical capped
        # to major at candidate, warning→major, note→minor, none/null→info); the
        # parser stamps evidence_type='static' + confidence='candidate' and
        # enforces the SCH-04 cap.
        findings = _sarif_to_findings(
            sarif,
            source_tool=_SOURCE_TOOL,
            default_dimension=_DIMENSION,
            severity_map={},
        )

        return AdapterResult(
            findings=findings,
            status="ok",
            source_adapter=_SOURCE_ADAPTER,
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
            scanned_paths=[str(native_root)],
            notes=f"mobsfscan: {len(findings)} finding(s)",
        )
    except Exception as exc:  # noqa: BLE001 — absolute never-raise backstop
        return AdapterResult(
            status="unavailable",
            source_adapter=_SOURCE_ADAPTER,
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
            notes=f"mobsfscan collection failed: {type(exc).__name__}: {exc}",
        )


def run_mobsfscan(
    native_root: Path,
    *,
    timeout_seconds: float = _MOBSFSCAN_TIMEOUT_SECONDS,
) -> AdapterResult:
    """Convenience wrapper: run :func:`collect_mobsfscan` with a default env.

    Builds a per-call cache-redirected scan env (mirrors how the SCA step seeds
    ``build_scan_env``) so callers/tests that don't already have an env can
    invoke the collector directly. Plan 05 calls ``collect_mobsfscan`` with the
    shared scan env instead; this wrapper is for the standalone/live path.
    """
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        return collect_mobsfscan(
            native_root, env=env, timeout_seconds=timeout_seconds
        )


__all__ = ["collect_mobsfscan", "run_mobsfscan"]
