"""PERF-01 web tier — live-URL-gated Lighthouse collector (Phase 15, Plan 03).

``collect_lighthouse`` is the never-raising collection function for the deep web
performance tier: it runs ``lighthouse`` (headless Chrome) against a CONFIGURED
live URL, reads the LHR JSON FILE (never stdout), and collapses it to ONE
aggregate ``quality`` perf Finding (+ independent oversized/regression triggers)
via :func:`lighthouse_json.map_lighthouse_json`.

It mirrors the live-URL-gate-FIRST resolve → gate → ``run_tool`` → read-the-FILE
shape of ``adapters/quality_depth/axe.py::collect_axe`` (Plan 02), in gate order:

    GATE 1 — LIVE-URL (SAFE-08 / T-15-08 / D-15-03). No ``live_url`` →
        ``status='unavailable'`` returned IMMEDIATELY, WITHOUT invoking any binary
        and WITHOUT resolving the tool. Providing the URL in
        ``.repo-audit.yaml`` IS the egress opt-in; absent URL → zero network
        egress, first-class tested (the SSRF/egress mitigation T-15-08).
    GATE 2 — ``resolve_tool("lighthouse", repo)`` with the DEFAULT
        ``trusted_only=False`` (lighthouse is an npm PROJECT tool — the
        knip/eslint/axe precedent; the node_modules walk-up IS the intended
        T-03-03 mitigation). A ``None`` → ``status='unavailable'``, ``run_tool``
        NOT invoked.
    GATE 3 — build the argv to a ``scan_tempdir()`` ``--output-path`` GUARANTEED
        outside the read-only target repo, invoke lighthouse through the single
        ``run_tool`` seam (shell=False, list[str], explicit timeout — FND-04 /
        T-15-10 / T-15-11). ``--chrome-flags="--headless --no-sandbox"`` (RESEARCH
        Pitfall 5 — Chrome cannot sandbox in many CI/container contexts).
    GATE 4 — map the ``run_tool`` sentinels: ``TIMED_OUT`` (-2) →
        ``status='timeout'`` (T-15-10 — never hangs); ``EXEC_FAILED`` (-1) or any
        other non-zero exit → ``unavailable``.
    GATE 5 — read + parse the LHR ``--output-path`` FILE (NOT stdout). A missing
        file / malformed JSON → ``status='unavailable'`` (never raises). A valid
        document → ``findings = map_lighthouse_json(lhr, config=...,
        prior_web_bytes=...)``, ``status='ok'``.

ALL subprocess work goes through the shared ``run_tool`` seam — this module NEVER
imports ``subprocess`` directly. ``resolve_tool`` / ``run_tool`` are re-exported as
module-level names so the no-egress / absent-binary / timeout tests can
``monkeypatch.setattr(lighthouse, …)``.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.quality_depth.lighthouse_json import map_lighthouse_json
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

if TYPE_CHECKING:
    from repo_audit.adapters.quality_depth.config import QualityDepthConfig

LighthouseStatus = Literal["ok", "unavailable", "timeout"]

_LIGHTHOUSE_TOOL = "lighthouse"
_DEFAULT_DIMENSION = "quality"
_DEFAULT_TIMEOUT = 120.0

# lighthouse writes the LHR JSON here inside the --output dir (FILE, not stdout).
_LHR_FILENAME = "lighthouse-lhr.json"


@dataclass
class LighthouseResult:
    """Never-raise envelope for :func:`collect_lighthouse`.

    Mirrors the quality_depth ``AxeResult`` / architecture ``DuplicationResult``
    envelope: every failure mode (no live_url, absent binary, exec-failure,
    timeout, missing/malformed LHR file) folds into ``status`` + ``notes`` rather
    than raised. ``status='ok'`` carries the aggregate perf finding(s).
    """

    findings: list[Finding] = field(default_factory=list)
    status: LighthouseStatus = "ok"
    notes: str = ""


def _lighthouse_argv(binary: Path, live_url: str, out_json: Path) -> list[str]:
    """Build the EXACT lighthouse argv (list[str], shell=False guard).

    ``<url>`` is the live target. ``--output json`` + ``--output-path <out_json>``
    pin the LHR to a FILE (Pitfall 2 — never parse stdout).
    ``--only-categories=performance`` scopes the run to the perf dimension.
    ``--chrome-flags="--headless --no-sandbox"`` (RESEARCH Pitfall 5) lets Chrome
    launch headless in CI/container contexts where the sandbox is unavailable.
    Each token is a DISCRETE argv element — never shell-interpolated (T-15-11).
    """
    return [
        str(binary),
        live_url,
        "--output",
        "json",
        "--output-path",
        str(out_json),
        "--only-categories=performance",
        "--chrome-flags=--headless --no-sandbox",
    ]


def collect_lighthouse(
    repo_path: Path,
    env: dict[str, str],
    *,
    live_url: str | None,
    config: "QualityDepthConfig | None" = None,
    prior_web_bytes: int | None = None,
    timeout_seconds: float | None = None,
) -> LighthouseResult:
    """Run Lighthouse against a configured live URL; return the web-perf findings.

    Args:
        repo_path: the target repository root (resolve_tool walk-up root + cwd).
        env: the child environment (cache-redirected by the caller).
        live_url: the configured live URL to audit. ``None`` → the SAFE-08
            no-egress degrade: ``status='unavailable'`` WITHOUT invoking any binary
            (providing the URL IS the egress opt-in, D-15-03 / T-15-08).
        config: the resolved :class:`QualityDepthConfig` (budget + regression).
        prior_web_bytes: an optional prior-scan ``web_transfer_bytes`` baseline
            forwarded to the mapper's regression trigger (None → baseline run).
        timeout_seconds: hard wall-clock bound; defaults to 120s.

    Returns:
        A :class:`LighthouseResult`. ``status='ok'`` with the aggregate perf
        finding(s) on success; ``status='unavailable'`` when no live_url is
        configured, lighthouse is absent / exec-failed / exits non-zero, or the
        LHR file is missing/malformed; ``status='timeout'`` on expiry. NEVER
        raises, NEVER hangs, NEVER egresses without a live_url.
    """
    repo_path = Path(repo_path)
    if timeout_seconds is None:
        timeout_seconds = _DEFAULT_TIMEOUT

    # GATE 1 — LIVE-URL (SAFE-08 / T-15-08). No URL → unavailable, NO binary
    # invoked, NO tool resolved, ZERO network egress. Return BEFORE anything else.
    if not live_url:
        return LighthouseResult(
            status="unavailable",
            notes="no live_url configured — runtime web perf skipped (SAFE-08)",
        )

    # GATE 2 — resolve the npm PROJECT tool (default trusted_only=False; the
    # node_modules walk-up IS the intended T-03-03 mitigation here). A None →
    # unavailable, run_tool NOT invoked.
    binary = resolve_tool(_LIGHTHOUSE_TOOL, repo_path)
    if binary is None:
        return LighthouseResult(
            status="unavailable",
            notes="lighthouse not found (node_modules + PATH miss)",
        )

    if config is None:
        from repo_audit.adapters.quality_depth.config import QualityDepthConfig

        config = QualityDepthConfig()

    with ExitStack() as stack:
        # GATE 3 — output dir GUARANTEED outside the read-only target (REP-03).
        out_dir = stack.enter_context(scan_tempdir())
        out_json = out_dir / _LHR_FILENAME

        invocation = run_tool(
            _lighthouse_argv(binary, live_url, out_json),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 4 — run_tool structural sentinels (these NEVER raise / hang).
        if invocation.returncode == TIMED_OUT:
            return LighthouseResult(
                status="timeout",
                notes=f"lighthouse exceeded {timeout_seconds:.0f}s",
            )
        if invocation.returncode == EXEC_FAILED:
            return LighthouseResult(
                status="unavailable",
                notes=f"lighthouse could not be executed: {invocation.stderr}",
            )
        if invocation.returncode != 0:
            # A non-zero, non-sentinel exit — e.g. a Chrome-sandbox failure
            # (RESEARCH Pitfall 5). Honest degrade, never a crash.
            return LighthouseResult(
                status="unavailable",
                notes=(
                    f"lighthouse exited {invocation.returncode} "
                    f"(no usable LHR): {invocation.stderr[:200]}"
                ),
            )

        # GATE 5 — read + parse the LHR FILE, NOT stdout. Missing / malformed →
        # unavailable (never raises).
        if not out_json.is_file():
            return LighthouseResult(
                status="unavailable",
                notes="lighthouse produced no LHR file",
            )
        try:
            lhr = json.loads(out_json.read_text(encoding="utf-8"))
            findings = map_lighthouse_json(
                lhr,
                config=config,
                default_dimension=_DEFAULT_DIMENSION,
                prior_web_bytes=prior_web_bytes,
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return LighthouseResult(
                status="unavailable",
                notes=f"lighthouse LHR parse failed: {type(exc).__name__}: {exc}",
            )

        return LighthouseResult(
            findings=findings,
            status="ok",
            notes=f"lighthouse: {len(findings)} web perf finding(s) from {live_url}",
        )


__all__ = [
    "LighthouseResult",
    "LighthouseStatus",
    "collect_lighthouse",
    "resolve_tool",
    "run_tool",
]
