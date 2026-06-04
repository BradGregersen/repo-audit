"""refresh_vuln_db (FND-03 / D-07-03 / CRIT-3) — the ONLY snapshot-advance path.

This module mirrors the STRUCTURAL posture of ``typescript/refresh.py`` (a small
pydantic ``*RefreshResult`` with ``extra="forbid"``, ``_scrub_secrets`` on the
child env, ``_redact_tail`` on the bounded stderr, a hard never-raises contract)
but invokes external binaries through the SHARED ``run_tool`` seam (FND-04) rather
than spawning processes directly — all new Phase 7+ tool-ops go through that
one audited path.

``refresh_vuln_db`` advances BOTH sources in ONE pass (D-07-03):

    * osv-scanner: ``scan source --offline-vulnerabilities
      --download-offline-databases --format json <throwaway-dir>`` — the
      ``--download-offline-databases`` flag is what advances the osv snapshot.
      osv requires a scan target to download against, so a throwaway empty
      tempdir is used (NOT a repo-derived path — T-07-17 argv-injection
      avoidance: the only path passed is a tool-controlled tempdir).
    * grype: ``db update`` — the explicit grype snapshot advance.

This is the SOLE code path in the codebase that passes
``--download-offline-databases`` / ``db update``. The normal scan path
(``run_sca``) NEVER advances the DB (D-07-01 seed-once-then-pin; CRIT-3
refresh-is-the-only-update). The first-run SEED (an absent DB) is handled
separately in ``run_sca`` — that seeds ONCE when no snapshot exists; this is the
EXPLICIT user-requested advance of an EXISTING snapshot.

Never raises across its boundary: ``run_tool`` sentinels (-1 exec-failed →
``failed``, -2 timed-out → ``timeout``) and a missing binary (``skipped``) are
all folded into the :class:`ScaRefreshResult`.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sca.db_env import build_sca_env
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

RefreshStatus = Literal["ok", "failed", "timeout", "skipped"]

# Refresh fetches a DB over the network; give it a generous bound (the seed of a
# fresh osv/grype DB can take a while on first download). Mirrors the long-running
# coverage-refresh timeout posture in typescript/refresh.py.
_REFRESH_TIMEOUT_SECONDS: float = 600.0

# Secret-shaped env key suffixes scrubbed from the child env before invocation
# (mirrors typescript/refresh.py ``_scrub_secrets``).
_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
)

# M2 / bound-output: the redacted stderr tail cap (mirrors refresh.py _TAIL_CAP).
_TAIL_CAP: int = 2048


class ScaRefreshResult(BaseModel):
    """Outcome of :func:`refresh_vuln_db` — folded into the scope ledger by run_sca.

    Mirrors ``typescript/refresh.py``'s ``RefreshResult`` shape; ``extra="forbid"``.
    ``status`` is the overall verdict; ``osv_status`` / ``grype_status`` are the
    per-source verdicts (so a partial refresh — one source advanced, one absent —
    is surfaced honestly).
    """

    model_config = ConfigDict(extra="forbid")
    status: RefreshStatus
    osv_status: RefreshStatus = "skipped"
    grype_status: RefreshStatus = "skipped"
    stdout_tail: str = ""
    stderr_tail: str = ""
    notes: str = ""
    duration_ms: float = 0.0


def _scrub_secrets(env: dict[str, str]) -> dict[str, str]:
    """Strip env vars whose name suffix-matches a secret-shaped pattern.

    Conservative: any ``*_TOKEN`` / ``*_KEY`` / ``*_SECRET`` / ``*_PASSWORD`` /
    ``*_PASSWD`` goes. False-positive stripping is acceptable; leaking a real
    secret into tool stderr is not. Returns a NEW dict.
    """
    return {
        k: v
        for k, v in env.items()
        if not any(k.upper().endswith(sfx) for sfx in _SECRET_KEY_SUFFIXES)
    }


def _redact_tail(text: str) -> str:
    """Truncate to ``_TAIL_CAP`` and apply the C13 secret-lint redaction.

    Defensive-in-depth at the tool-invocation boundary; the render-time chokepoint is
    the final guard. A secret-lint hit becomes a value-blind notice, not a crash.
    """
    snippet = text[-_TAIL_CAP:] if len(text) > _TAIL_CAP else text
    try:
        from repo_audit.render.secret_lint import SecretsDetected, lint_buffer

        try:
            lint_buffer(snippet, buffer_name="vuln_db_refresh_stderr")
        except SecretsDetected as hits:
            return (
                f"[REDACTED: {len(snippet)} chars contained "
                f"{len(hits.hits)} potential secrets]"
            )
    except Exception:  # pragma: no cover — defensive
        pass
    return snippet


def _classify(returncode: int) -> RefreshStatus:
    """Map a run_tool returncode to a refresh status (never the wrapper raising)."""
    if returncode == TIMED_OUT:
        return "timeout"
    if returncode == EXEC_FAILED:
        return "failed"
    if returncode == 0:
        return "ok"
    # A non-zero tool exit that is NOT a sentinel: the advance ran but the tool
    # reported a problem (e.g. network error). Treat as failed for honesty.
    return "failed"


def _overall(osv: RefreshStatus, grype: RefreshStatus) -> RefreshStatus:
    """Combine per-source statuses into the overall verdict.

    "ok" only if at least one source advanced and none failed/timed-out;
    "timeout" if any timed out; else "failed" unless both were merely skipped.
    """
    statuses = {osv, grype}
    if "timeout" in statuses:
        return "timeout"
    if "failed" in statuses:
        return "failed"
    if "ok" in statuses:
        return "ok"
    return "skipped"


def refresh_vuln_db(env: dict[str, str]) -> ScaRefreshResult:
    """Advance the pinned osv + grype vuln-DB snapshots in one pass (D-07-03).

    Args:
        env: the base child environment. ``build_sca_env`` is layered on top (the
            persistent DB-cache dirs) and ``_scrub_secrets`` removes secret-shaped
            keys before invocation.

    Returns:
        A :class:`ScaRefreshResult`; never raises across its boundary. This is the
        SOLE path that passes ``--download-offline-databases`` / ``db update``.
    """
    t0 = time.perf_counter()
    db_env = _scrub_secrets(build_sca_env(env))

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []

    # A throwaway scan target for osv's download pass — never a repo-derived path
    # (T-07-17). resolve_tool's scan_target only drives vendor/PATH lookup; the
    # vendored binary wins regardless, so the tempdir is a safe lookup root too.
    with tempfile.TemporaryDirectory(prefix="repo-vulndb-refresh-") as td:
        target = Path(td)

        # --- osv advance ---------------------------------------------------
        osv_bin = resolve_tool("osv-scanner", target, trusted_only=True)
        if osv_bin is None:
            osv_status: RefreshStatus = "skipped"
        else:
            osv_argv = [
                str(osv_bin),
                "scan",
                "source",
                "--offline-vulnerabilities",
                "--download-offline-databases",
                "--format",
                "json",
                str(target),
            ]
            osv_inv = run_tool(
                osv_argv,
                env=db_env,
                cwd=target,
                timeout_seconds=_REFRESH_TIMEOUT_SECONDS,
            )
            osv_status = _classify(osv_inv.returncode)
            stdout_parts.append(osv_inv.stdout or "")
            stderr_parts.append(osv_inv.stderr or "")

        # --- grype advance -------------------------------------------------
        grype_bin = resolve_tool("grype", target, trusted_only=True)
        if grype_bin is None:
            grype_status: RefreshStatus = "skipped"
        else:
            # Refresh is the EXPLICIT advance: leave GRYPE_DB_AUTO_UPDATE at its
            # default for the update call (db update advances unconditionally).
            grype_argv = [str(grype_bin), "db", "update"]
            grype_inv = run_tool(
                grype_argv,
                env=db_env,
                cwd=target,
                timeout_seconds=_REFRESH_TIMEOUT_SECONDS,
            )
            grype_status = _classify(grype_inv.returncode)
            stdout_parts.append(grype_inv.stdout or "")
            stderr_parts.append(grype_inv.stderr or "")

    duration_ms = (time.perf_counter() - t0) * 1000.0
    notes = f"vuln-db refresh: osv={osv_status}, grype={grype_status}"

    return ScaRefreshResult(
        status=_overall(osv_status, grype_status),
        osv_status=osv_status,
        grype_status=grype_status,
        stdout_tail=_redact_tail("\n".join(p for p in stdout_parts if p)),
        stderr_tail=_redact_tail("\n".join(p for p in stderr_parts if p)),
        notes=notes,
        duration_ms=duration_ms,
    )


__all__ = ["ScaRefreshResult", "RefreshStatus", "refresh_vuln_db"]
