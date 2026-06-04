"""A11Y-01 runtime tier — live-URL-gated @axe-core/cli collector (Phase 15).

``collect_axe`` is the never-raising collection function for the deep web
accessibility tier: it loads a CONFIGURED live URL in headless Chrome via
``@axe-core/cli``, reads axe's results JSON FILE (never stdout), and maps each
WCAG violation to one ``quality`` runtime Finding via
:func:`axe_json.map_axe_json`.

It follows the canonical resolve → gate → ``run_tool`` → read-the-FILE shape of
``adapters/architecture/duplication.py::collect_jscpd``, but with the LIVE-URL
GATE FIRST (the SAFE-08 no-egress contract), in gate order:

    GATE 1 — LIVE-URL (SAFE-08 / T-15-03 / D-15-03). No ``live_url`` →
        ``status='unavailable'`` returned IMMEDIATELY, WITHOUT invoking any
        binary and WITHOUT resolving the tool. Providing the URL in
        ``.repo-audit.yaml`` IS the egress opt-in; absent URL → zero
        network egress, first-class tested.
    GATE 2 — ``resolve_tool("axe", repo)`` with the DEFAULT ``trusted_only=False``
        (``@axe-core/cli`` is an npm PROJECT tool — the knip/eslint precedent;
        the node_modules walk-up IS the intended T-03-03 mitigation). A ``None``
        → ``status='unavailable'``, ``run_tool`` NOT invoked.
    GATE 3 — build the argv to a ``scan_tempdir()`` output GUARANTEED outside the
        read-only target repo, invoke axe through the single ``run_tool`` seam
        (shell=False, list[str], explicit timeout — FND-04 / T-15-05 / T-15-06).
        ``--save <out_json>`` + ``--dir <out_dir>`` pin axe's report to a FILE
        (RESEARCH Open-Q1 Wave-0 flag check).
    GATE 4 — map the ``run_tool`` sentinels: ``TIMED_OUT`` (-2) →
        ``status='timeout'`` (T-15-05 — never hangs); any other non-zero exit
        (e.g. a Chrome-sandbox failure — RESEARCH Pitfall 5) → ``unavailable``.
    GATE 5 — read + parse ``<out_json>`` (the FILE, NOT stdout). A missing file /
        malformed JSON → ``status='unavailable'`` (never raises). A valid
        document → ``findings = map_axe_json(report)``, ``status='ok'``.

ALL subprocess work goes through the shared ``run_tool`` seam — this module
NEVER imports ``subprocess`` directly. ``resolve_tool`` / ``run_tool`` are
re-exported as module-level names so the absent-binary / timeout / no-egress
tests can ``monkeypatch.setattr(axe, …)``.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.quality_depth.axe_json import map_axe_json
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

AxeStatus = Literal["ok", "unavailable", "timeout"]

_AXE_TOOL = "axe"  # the @axe-core/cli bin is `axe`
_AXE_DEFAULT_DIMENSION = "quality"
_AXE_DEFAULT_TIMEOUT = 120.0

# axe writes its results JSON here inside the --dir output dir (FILE, not stdout).
_RESULTS_FILENAME = "axe-results.json"


@dataclass
class AxeResult:
    """Never-raise envelope for :func:`collect_axe`.

    Mirrors the architecture ``DuplicationResult`` envelope: every failure mode
    (no live_url, absent binary, exec-failure, timeout, missing/malformed report
    file) folds into ``status`` + ``notes`` rather than raised. ``status='ok'``
    carries the per-violation quality/runtime/candidate findings.
    """

    findings: list[Finding] = field(default_factory=list)
    status: AxeStatus = "ok"
    notes: str = ""


def _axe_argv(binary: Path, live_url: str, out_json: Path, out_dir: Path) -> list[str]:
    """Build the EXACT @axe-core/cli argv (list[str], shell=False guard).

    ``<url>`` is the live target; ``--save <out_json>`` writes the results JSON
    to a FILE (Pitfall 2 — never parse stdout); ``--dir <out_dir>`` pins the
    output directory (RESEARCH Open-Q1). Each token is a DISCRETE argv element —
    never shell-interpolated (T-15-06).
    """
    return [
        str(binary),
        live_url,
        "--save",
        str(out_json),
        "--dir",
        str(out_dir),
    ]


def collect_axe(
    repo_path: Path,
    env: dict[str, str],
    *,
    live_url: str | None,
    timeout_seconds: float | None = None,
) -> AxeResult:
    """Run axe-core against a configured live URL; return the a11y findings.

    Args:
        repo_path: the target repository root (resolve_tool walk-up root + cwd).
        env: the child environment (cache-redirected by the caller).
        live_url: the configured live URL to audit. ``None`` → the SAFE-08
            no-egress degrade: ``status='unavailable'`` WITHOUT invoking any
            binary (providing the URL IS the egress opt-in, D-15-03).
        timeout_seconds: hard wall-clock bound; defaults to 120s.

    Returns:
        An :class:`AxeResult`. ``status='ok'`` with the per-violation
        quality/runtime/candidate findings on success; ``status='unavailable'``
        when no live_url is configured, axe is absent / exec-failed, or the
        results file is missing/malformed; ``status='timeout'`` on expiry. NEVER
        raises, NEVER hangs, NEVER egresses without a live_url.
    """
    repo_path = Path(repo_path)
    if timeout_seconds is None:
        timeout_seconds = _AXE_DEFAULT_TIMEOUT

    # GATE 1 — LIVE-URL (SAFE-08 / T-15-03). No URL → unavailable, NO binary
    # invoked, NO tool resolved, ZERO network egress. Return BEFORE anything else.
    if not live_url:
        return AxeResult(
            status="unavailable",
            notes="no live_url configured — runtime a11y skipped (SAFE-08)",
        )

    # GATE 2 — resolve the npm PROJECT tool (default trusted_only=False; the
    # node_modules walk-up IS the intended T-03-03 mitigation here). A None →
    # unavailable, run_tool NOT invoked.
    binary = resolve_tool(_AXE_TOOL, repo_path)
    if binary is None:
        return AxeResult(
            status="unavailable",
            notes="@axe-core/cli (axe) not found (node_modules + PATH miss)",
        )

    with ExitStack() as stack:
        # GATE 3 — output dir GUARANTEED outside the read-only target (REP-03).
        out_dir = stack.enter_context(scan_tempdir())
        out_json = out_dir / _RESULTS_FILENAME

        invocation = run_tool(
            _axe_argv(binary, live_url, out_json, out_dir),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 4 — run_tool structural sentinels (these NEVER raise / hang).
        if invocation.returncode == TIMED_OUT:
            return AxeResult(
                status="timeout",
                notes=f"axe exceeded {timeout_seconds:.0f}s",
            )
        if invocation.returncode == EXEC_FAILED:
            return AxeResult(
                status="unavailable",
                notes=f"axe could not be executed: {invocation.stderr}",
            )
        if invocation.returncode != 0:
            # A non-zero, non-sentinel exit — e.g. a Chrome-sandbox failure
            # (RESEARCH Pitfall 5). Honest degrade, never a crash.
            return AxeResult(
                status="unavailable",
                notes=(
                    f"axe exited {invocation.returncode} "
                    f"(no usable results): {invocation.stderr[:200]}"
                ),
            )

        # GATE 5 — read + parse the results FILE, NOT stdout. Missing /
        # malformed → unavailable (never raises).
        if not out_json.is_file():
            return AxeResult(
                status="unavailable",
                notes="axe produced no results file",
            )
        try:
            report = json.loads(out_json.read_text(encoding="utf-8"))
            findings = map_axe_json(
                report, default_dimension=_AXE_DEFAULT_DIMENSION
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return AxeResult(
                status="unavailable",
                notes=f"axe results parse failed: {type(exc).__name__}: {exc}",
            )

        return AxeResult(
            findings=findings,
            status="ok",
            notes=f"axe: {len(findings)} a11y violation finding(s) from {live_url}",
        )


__all__ = [
    "AxeResult",
    "AxeStatus",
    "collect_axe",
    "resolve_tool",
    "run_tool",
]
