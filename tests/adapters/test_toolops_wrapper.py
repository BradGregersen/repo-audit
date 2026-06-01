"""FND-04 / SC-4 contract tests for the shared ``run_tool`` subprocess wrapper.

The wrapper is the single audited tool-ops seam every Phase 7–16 scanner
invokes external binaries through. These tests pin its load-bearing
guarantees:

    * shell=False ALWAYS + ``list[str]`` argv (TypeError on a str argv —
      T-06-01 structural shell-injection guard, T-03-02 lineage).
    * Happy path returns a fully-populated ``InvocationResult`` (returncode 0).
    * Timeout escalates SIGTERM → 5s → SIGKILL and returns the existing
      ``returncode == -2`` sentinel — NEVER re-raises, NEVER hangs (T-06-02).
    * A SIGTERM-trapping child is still SIGKILLed within the grace window.
    * A missing binary returns ``returncode == -1`` (exec-failed) — no raise.

The timeout / SIGKILL tests use a REAL short-lived subprocess (not
pytest-subprocess) because the escalation ladder + no-hang property is a
property of the real OS process lifecycle, and pytest-subprocess cannot model
a child that ignores SIGTERM. They ``skipif`` on non-POSIX where signal
semantics differ.
"""
from __future__ import annotations

import os
import sys
import time

import pytest

from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.toolops import run_tool

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="SIGTERM→SIGKILL escalation semantics are POSIX-specific",
)


def test_shell_false_list_argv(fp):
    """A str argv raises TypeError; a list argv runs (T-06-01)."""
    with pytest.raises(TypeError):
        run_tool(
            "echo hi",  # type: ignore[arg-type]
            env={},
            cwd=os.getcwd(),
            timeout_seconds=5.0,
        )

    fp.register(["sometool"], stdout="ok\n", returncode=0)
    result = run_tool(
        ["sometool"],
        env={},
        cwd=os.getcwd(),
        timeout_seconds=5.0,
    )
    assert isinstance(result, InvocationResult)
    assert result.returncode == 0


def test_happy_path_returns_invocation_result(fp):
    """A canned fp response populates every field; returncode 0."""
    fp.register(
        ["mytool", "--flag"],
        stdout="line1\nline2\n",
        stderr="warn\n",
        returncode=0,
    )
    result = run_tool(
        ["mytool", "--flag"],
        env={"PATH": "/usr/bin"},
        cwd=os.getcwd(),
        timeout_seconds=10.0,
    )
    assert result.returncode == 0
    assert "line1" in result.stdout
    assert "warn" in result.stderr
    assert result.command == ["mytool", "--flag"]
    assert result.duration_ms >= 0.0


def test_nonzero_returncode_preserved(fp):
    """A tool that exits non-zero surfaces its real returncode (not -1/-2)."""
    fp.register(["lintish"], stdout="", stderr="found issues\n", returncode=3)
    result = run_tool(
        ["lintish"],
        env={},
        cwd=os.getcwd(),
        timeout_seconds=5.0,
    )
    assert result.returncode == 3
    assert "found issues" in result.stderr


@_POSIX_ONLY
def test_timeout_returns_sentinel_minus_two():
    """A genuine blocking command past the timeout → returncode -2, no hang."""
    t0 = time.perf_counter()
    result = run_tool(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        env=dict(os.environ),
        cwd=os.getcwd(),
        timeout_seconds=0.5,
    )
    wall = time.perf_counter() - t0
    assert result.returncode == -2, "timeout must map to the -2 sentinel"
    # Proves it does NOT hang: the child slept 5s but we bail well before.
    assert wall < 3.0, f"run_tool hung for {wall:.1f}s on a 0.5s timeout"


@_POSIX_ONLY
def test_sigkill_escalation_on_sigterm_ignored():
    """A child that traps SIGTERM is still SIGKILLed within the grace window."""
    # Install a SIGTERM handler that ignores it, then sleep long.
    script = (
        "import signal, time, sys\n"
        "signal.signal(signal.SIGTERM, lambda *a: None)\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    t0 = time.perf_counter()
    result = run_tool(
        [sys.executable, "-c", script],
        env=dict(os.environ),
        cwd=os.getcwd(),
        timeout_seconds=0.5,
    )
    wall = time.perf_counter() - t0
    assert result.returncode == -2
    # 0.5s timeout + 5s SIGTERM grace + kill → must finish well under ~8s and
    # never hang on the 60s sleep.
    assert wall < 8.0, f"SIGKILL escalation took {wall:.1f}s (expected <8s)"


def test_never_raises_on_missing_binary():
    """argv pointing at a nonexistent path → returncode -1, no raise."""
    result = run_tool(
        ["/nonexistent/definitely-not-a-real-binary-xyz"],
        env={},
        cwd=os.getcwd(),
        timeout_seconds=5.0,
    )
    assert result.returncode == -1
    assert result.stderr  # an honest reason string is present
