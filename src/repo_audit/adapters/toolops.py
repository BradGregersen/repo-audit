"""FND-04 / SC-4 — the single shared tool-ops subprocess wrapper.

Every Phase 7–16 scanner that shells out to an external binary (osv-scanner,
Semgrep, mobsfscan, detekt, …) MUST invoke it through ``run_tool`` rather than
calling ``subprocess`` directly. One audited seam — reused ~10× — enforces the
whole ops posture in a single place (D-06-09):

    * ``shell=False`` ALWAYS; ``argv`` is a ``list[str]``. Passing a ``str``
      raises ``TypeError`` — a structural guard against shell-string injection
      (T-06-01, T-03-02 lineage). No shell metacharacter interpretation is ever
      possible.
    * An explicit per-call ``timeout_seconds``. On a hang we escalate
      ``SIGTERM`` → wait 5 s → ``SIGKILL`` (the same ladder the codebase already
      uses for per-collector wall-clock bounding — see
      ``collectors/_budget.py``). A child that ignores ``SIGTERM`` is still
      reaped, so ``run_tool`` NEVER hangs (T-06-02).
    * The wrapper NEVER raises across its boundary. Every failure mode is
      folded into an :class:`InvocationResult` with an honest structural
      sentinel returncode:

          returncode == -1  →  could-not-exec (binary vanished / OSError).
                               Caller maps this to ``status='unavailable'``.
          returncode == -2  →  timed-out (SIGTERM→SIGKILL escalation fired).
                               Caller maps this to ``status='timeout'``.

      Any other returncode is the real exit status of the tool and is passed
      through verbatim (a non-zero lint exit is NOT a wrapper failure).

We use ``subprocess.Popen`` + ``communicate(timeout=…)`` rather than
``subprocess.run(timeout=…)`` precisely because ``run`` does NOT perform the
graceful SIGTERM→5s→SIGKILL escalation FND-04 specifies — on ``TimeoutExpired``
it sends a single ``SIGKILL`` to the *immediate* child only. The explicit
``terminate()`` → ``communicate(timeout=5)`` → ``kill()`` ladder below gives a
well-behaved child the chance to flush/clean up while still guaranteeing a
SIGTERM-ignoring child is killed.

stdout/stderr are captured as text and any undecodable bytes are replaced
(``errors='replace'``) — mirrors the existing TypeScript adapter / refresh code
path. Output is bounded by the timeout (T-06-04 disposition: accept; an
explicit byte cap is deferred until real workloads inform the size, same
rationale as Phase 3).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from repo_audit.adapters.base import InvocationResult

# Structural sentinel returncodes (documented in the module docstring above).
EXEC_FAILED: int = -1  # binary could not be exec'd → caller: unavailable
TIMED_OUT: int = -2  # timeout + SIGTERM→SIGKILL escalation → caller: timeout

# Grace period between SIGTERM and SIGKILL. Mirrors the SIGTERM→5s→SIGKILL
# shape referenced by collectors/_budget.py.
_SIGTERM_GRACE_SECONDS: float = 5.0


def _decode(stream: str | bytes | None) -> str:
    """Decode a captured stream to text, replacing undecodable bytes."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream


def run_tool(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: str | Path,
    timeout_seconds: float,
) -> InvocationResult:
    """Invoke ``argv`` under ``env``/``cwd`` with an explicit timeout.

    Args:
        argv: the command as a ``list[str]`` (``argv[0]`` is the binary path or
            name). Passing a ``str`` raises ``TypeError`` — shell-injection
            guard (T-06-01).
        env: the environment mapping for the child (e.g. a cache-redirected env
            from ``build_scan_env``).
        cwd: working directory for the child.
        timeout_seconds: hard wall-clock bound. On expiry the child is
            terminated (SIGTERM→5s→SIGKILL) and ``returncode == -2`` is
            returned.

    Returns:
        An :class:`InvocationResult`. ``returncode == -1`` means exec failed
        (binary missing / OSError); ``returncode == -2`` means the call timed
        out; any other value is the tool's real exit status.

    Raises:
        TypeError: if ``argv`` is a ``str`` rather than a ``list[str]``. This
            is the ONLY exception ``run_tool`` raises — it is a programming
            error caught at the call site, not a runtime tool failure.
    """
    if isinstance(argv, str):
        raise TypeError(
            "run_tool requires a list[str] argv (shell=False); a str argv "
            "would invite shell-string injection (T-06-01). "
            f"Got: {argv!r}"
        )

    command = list(argv)
    t0 = time.perf_counter()

    try:
        proc = subprocess.Popen(
            command,
            shell=False,
            env=env,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
    except FileNotFoundError as exc:
        # Binary vanished between resolution and invocation, or argv[0] is a
        # path that does not exist. -1 = could-not-exec; never raise.
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return InvocationResult(
            stdout="",
            stderr=f"run_tool: binary not found: {exc}",
            returncode=EXEC_FAILED,
            command=command,
            duration_ms=duration_ms,
        )
    except OSError as exc:
        # Permission denied, not-executable, etc. Same disposition as missing.
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return InvocationResult(
            stdout="",
            stderr=f"run_tool: could not exec: {type(exc).__name__}: {exc}",
            returncode=EXEC_FAILED,
            command=command,
            duration_ms=duration_ms,
        )

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return InvocationResult(
            stdout=_decode(stdout),
            stderr=_decode(stderr),
            returncode=proc.returncode,
            command=command,
            duration_ms=duration_ms,
        )
    except subprocess.TimeoutExpired:
        # SIGTERM→5s→SIGKILL escalation. A well-behaved child exits on
        # terminate(); one that traps SIGTERM is SIGKILLed after the grace.
        stdout, stderr = _terminate_then_kill(proc)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return InvocationResult(
            stdout=_decode(stdout),
            stderr=_decode(stderr),
            returncode=TIMED_OUT,
            command=command,
            duration_ms=duration_ms,
        )


def _terminate_then_kill(
    proc: subprocess.Popen,
) -> tuple[str | bytes | None, str | bytes | None]:
    """SIGTERM → wait 5 s → SIGKILL escalation; drain output, never hang.

    Returns whatever stdout/stderr could be drained. Always returns — a child
    that ignores SIGTERM is SIGKILLed and reaped so this cannot block
    indefinitely.
    """
    # Step 1: polite SIGTERM, give the child the grace window to flush + exit.
    proc.terminate()
    try:
        return proc.communicate(timeout=_SIGTERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass

    # Step 2: child ignored SIGTERM — SIGKILL and reap unconditionally.
    proc.kill()
    try:
        return proc.communicate(timeout=_SIGTERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        # Extraordinarily unlikely after SIGKILL; return what we can rather
        # than re-raise, honouring the never-raise contract.
        return "", "run_tool: child unresponsive after SIGKILL"


__all__ = ["run_tool", "EXEC_FAILED", "TIMED_OUT"]
