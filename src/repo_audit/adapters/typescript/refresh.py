"""D-41' opt-in coverage refresh — test-runner subprocess invocation.

Public API: ``refresh_coverage(repo_root, cfg, env) -> RefreshResult``.

SCOPE: refresh.py is the orchestration primitive only. It does NOT
construct any Finding object. The runner-failure Finding shape lives in
plan 03-03's ``_refresh_failed_finding(refresh_result, runner_command)``
helper, which plan 03-05's CLI failure-synthesis path calls. This
separation keeps the Finding schema import boundary in the parsers
module where the schema imports already live.

Layered defenses (T-03-refresh-*):
    * subprocess.run with shell=False, list[str] argv (T-03-refresh-injection)
    * Explicit timeout from cfg['timeout_ms'] (T-03-refresh-dos)
    * Env scrub of secret-shaped variables (T-03-refresh-env-leak)
    * C13 redaction on stderr tail (T-03-refresh-secret-disclosure)
    * Both stdout_tail AND stderr_tail bounded to ≤2 KB (M2 bound output)

Accepted (documented, NOT mitigated in Phase 3):
    * T-03-refresh-supplychain: target-repo's package.json ``test`` script
      may execute arbitrary code (e.g. postinstall hooks if running after
      ``npm install``). Users opting into refresh accept this; the tool's
      threat model assumes the user runs against repos they trust.
    * T-03-refresh-egress: network egress during the test run is permitted;
      Phase 7+ may add firejail/bwrap sandboxing.

Forbidden-literal discipline (mirrors plan 03-03's pattern): this module
intentionally does NOT pull in the parsers' schema module nor reference
the parsers' Finding constructor by name. Those literals are absent from
the source on purpose; ``test_refresh_does_not_import_finding`` greps the
module source to pin the separation.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RefreshStatus = Literal["ok", "failed", "timeout", "skipped"]


class RefreshResult(BaseModel):
    """Outcome of ``refresh_coverage()`` — surfaced into ScopeLedger by cli.py.

    Bounds (M2 / T-03-refresh-dos):
        * ``stdout_tail`` and ``stderr_tail`` are each ≤2048 bytes (2 KB).
        * Truncation happens at construction via ``_redact_tail``; downstream
          consumers (plan 03-03's ``_refresh_failed_finding``) do NOT
          re-truncate.

    No Finding construction here — refresh.py is the orchestration primitive.
    Plan 03-03 owns the Finding schema boundary via ``_refresh_failed_finding``.
    """

    model_config = ConfigDict(extra="forbid")
    status: RefreshStatus
    runner_command: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    stdout_tail: str = ""        # ≤ 2 KB; capped by _redact_tail
    stderr_tail: str = ""        # ≤ 2 KB; capped by _redact_tail + C13 redacted
    lcov_produced: bool = False
    notes: str = ""
    exit_code: int | None = None  # subprocess returncode when known; None on timeout/OSError


# ---------------------------------------------------------------------------
# Module-level constants

_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
)

# M2 / T-03-refresh-dos: bound both tail buffers to 2 KB at construction.
# Plan 03-03's ``_refresh_failed_finding`` relies on this bound and does NOT
# re-truncate. Keep this constant the single source of truth.
_TAIL_CAP: int = 2048

_LCOV_REL: str = "coverage/lcov.info"


# ---------------------------------------------------------------------------
# Private helpers


def _scrub_secrets(env: dict[str, str]) -> dict[str, str]:
    """Strip env vars whose name suffix-matches a secret-shaped pattern.

    Conservative: any ``*_TOKEN``, ``*_KEY``, ``*_SECRET``, ``*_PASSWORD``,
    ``*_PASSWD`` goes. False-positive stripping (e.g. ``PUBLIC_KEY``) is
    acceptable; false-negative (leaking a real secret) is not. Returns a
    NEW dict — does not mutate the input.
    """
    return {
        k: v
        for k, v in env.items()
        if not any(k.upper().endswith(sfx) for sfx in _SECRET_KEY_SUFFIXES)
    }


def _redact_tail(text: str) -> str:
    """Truncate to ``_TAIL_CAP`` and apply C13 redaction.

    The renderer chokepoint (Phase 1 D-07) remains the final structural
    guard; this is defensive-in-depth at the subprocess boundary. When the
    secret_lint primitive raises, that signal is escalated — the rendered
    report would be refused at write-time anyway, so a hit at the refresh
    boundary becomes a redacted notice rather than a crash.
    """
    snippet = text[-_TAIL_CAP:] if len(text) > _TAIL_CAP else text
    try:
        from repo_audit.render.secret_lint import lint_buffer, SecretsDetected

        try:
            lint_buffer(snippet, buffer_name="refresh_stderr")
        except SecretsDetected as hits:
            return (
                f"[REDACTED: {len(snippet)} chars contained "
                f"{len(hits.hits)} potential secrets]"
            )
    except Exception:  # pragma: no cover — defensive
        pass
    return snippet


# ---------------------------------------------------------------------------
# Public entry point


def refresh_coverage(
    repo_root: Path,
    cfg: dict,
    env: dict[str, str],
) -> RefreshResult:
    """Invoke the target-repo's test runner to produce ``coverage/lcov.info``.

    Never raises across the function boundary. Returns ONLY ``RefreshResult``
    (data) — does NOT construct any Finding. The Finding-shape boundary is
    plan 03-03's ``_refresh_failed_finding(refresh_result, runner_command)``.
    See module docstring for threat-model dispositions.

    Args:
        repo_root: target repo root (cwd for the subprocess).
        cfg: dict from adapter.yaml ``tools.coverage_refresh`` block, e.g.
            ``{'mode': 'auto', 'command': ['npm', 'test'], 'timeout_ms': 600000}``.
            Caller ensures ``mode != 'off'`` before calling (this function
            does NOT re-check mode).
        env: env dict from ``build_scan_env()``; ``refresh_coverage`` applies
            an ADDITIONAL secret-shaped-key scrub on top.

    Returns:
        ``RefreshResult``; never raises across the function boundary.
    """
    argv = list(cfg.get("command") or ["npm", "test"])
    timeout_s = float(cfg.get("timeout_ms", 600_000)) / 1000.0
    scrubbed_env = _scrub_secrets(env)
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(
            argv,
            cwd=str(repo_root),
            env=scrubbed_env,
            shell=False,                # CLAUDE.md / M2/M6 hard rule
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        raw_stderr = e.stderr
        if isinstance(raw_stderr, bytes):
            stderr_text = raw_stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = raw_stderr or ""
        return RefreshResult(
            status="timeout",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail="",
            stderr_tail=_redact_tail(stderr_text),
            lcov_produced=False,
            notes=f"timeout after {timeout_s:.1f}s",
            exit_code=None,
        )
    except (FileNotFoundError, OSError) as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return RefreshResult(
            status="failed",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail="",
            stderr_tail="",
            lcov_produced=False,
            notes=f"coverage_refresh_failed: {type(e).__name__}: {e}",
            exit_code=None,
        )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    lcov_produced = (repo_root / _LCOV_REL).is_file()
    stdout_tail = _redact_tail(cp.stdout or "")
    stderr_tail = _redact_tail(cp.stderr or "")

    if cp.returncode == 0 and lcov_produced:
        return RefreshResult(
            status="ok",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
            lcov_produced=True,
            notes="coverage refreshed",
            exit_code=0,
        )

    if cp.returncode != 0:
        return RefreshResult(
            status="failed",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
            lcov_produced=lcov_produced,
            notes=(
                f"coverage_refresh_failed: runner exit {cp.returncode}; "
                f"{stderr_tail[:200]}"
            ),
            exit_code=cp.returncode,
        )

    # returncode 0 but no lcov produced — test script didn't generate coverage.
    return RefreshResult(
        status="failed",
        runner_command=argv,
        duration_ms=elapsed_ms,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        lcov_produced=False,
        notes=(
            "coverage_refresh_failed: runner exited 0 but coverage/lcov.info "
            "not produced"
        ),
        exit_code=cp.returncode,
    )


__all__ = [
    "RefreshResult",
    "RefreshStatus",
    "refresh_coverage",
]
