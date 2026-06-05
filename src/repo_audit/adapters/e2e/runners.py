"""E2E harness argv builders (E2E-01, Plan 16-02 — Task 2).

Pure ``list[str]`` argv builders, mirroring ``sast.semgrep._semgrep_argv``: NO
subprocess here, NO I/O — argv only, so the run envelope can pass them straight
to the single shared ``run_tool`` seam (shell=False, list[str] only). Each
builder runs ONLY what the target repo already declares (its existing harness +
specs); none ever authors a spec or instruments the repo (D-25 / T-16-02-04).
"""
from __future__ import annotations

from pathlib import Path


def playwright_argv(binary: Path, repo: Path) -> list[str]:
    """Build the Playwright ``test`` argv with JSON reporting.

    ``--reporter=json`` selects the machine-readable result shape the
    :mod:`repo_audit.adapters.e2e.parsers` module consumes. ``repo`` is
    accepted for symmetry with the other builders (Playwright runs from cwd, set
    by ``run_tool``); it is never interpolated into a shell string.
    """
    _ = repo  # cwd is supplied to run_tool; kept for builder symmetry.
    return [str(binary), "test", "--reporter=json"]


def maestro_argv(binary: Path, flows_dir: Path, out_junit: Path) -> list[str]:
    """Build the Maestro ``test`` argv emitting a JUnit report to ``out_junit``.

    ``out_junit`` is the caller's scratch path (OUTSIDE the target repo —
    T-16-02-04), so reading the result never requires dirtying the tree.
    """
    return [
        str(binary),
        "test",
        str(flows_dir),
        "--format",
        "junit",
        "--output",
        str(out_junit),
    ]


def detox_argv(binary: Path, configuration: str = "android.emu.debug") -> list[str]:
    """Build the Detox ``test`` argv for a named configuration.

    Detox emits its own JUnit/Jest result; the run envelope reads whatever the
    repo's configured reporter produced. ``configuration`` names a pre-existing
    Detox config in the repo — never one this tool authors.
    """
    return [str(binary), "test", "--configuration", configuration]


__all__ = ["playwright_argv", "maestro_argv", "detox_argv"]
