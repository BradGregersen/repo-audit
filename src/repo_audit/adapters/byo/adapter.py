"""Generic BYO adapter: attestation gate -> shared SARIF pipeline (D-06-08 / SC-6).

``run_byo_tool`` is the generic seam an arbitrary commercial tool plugs into.
It does TWO things and nothing tool-specific:

    1. **Gates on the attestation** (D-06-06). If ``cfg.should_run`` is False the
       tool NEVER runs — the function returns ``status='unavailable'`` and the
       SARIF file is never even opened. This short-circuit is the load-bearing
       default-OFF guarantee (a disabled/unattested tool produces no findings
       and touches nothing).
    2. **Routes the tool's SARIF through the SAME ``sarif_to_findings``** every
       OSS tool uses (no forked parse path) — so a BYO finding is structurally
       identical to an OSS finding, tagged with ``source_tool=cfg.name``
       (BYO-01 traceability). The candidate severity cap (06-01 contract)
       therefore applies uniformly: a tool-reported critical surfaces as
       ``severity='major' + confidence='candidate' + caveat``.

Like every adapter (``adapters/base.py`` D-25 contract) this NEVER raises across
the orchestrator boundary — a missing/invalid SARIF file is folded into
``status='unavailable'`` with a ``notes`` reason.

Phase-16 seam
-------------
In Phase 6 we prove the PATTERN by reading a PRE-WRITTEN SARIF doc from
``cfg.sarif_output``. Phase 16 inserts the live-invocation step here: it will
run the commercial binary (via ``adapters.toolops.run_tool``, with the token
read from ``os.environ[cfg.credential_env]``) to PRODUCE ``cfg.sarif_output``
before this read. Everything downstream of the read is already final.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.byo.config import ByoToolConfig
from repo_audit.adapters.sarif import sarif_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

_SOURCE_ADAPTER = "byo"


def run_byo_tool(
    cfg: ByoToolConfig,
    repo_path: str | Path,
    *,
    produce_argv: list[str] | None = None,
    base_env: dict[str, str] | None = None,
    sarif_from_stdout: bool = False,
) -> AdapterResult:
    """Run a single BYO opt-in tool: gate on attestation, then route its SARIF.

    Args:
        cfg: the validated per-tool opt-in config (the attestation gate).
        repo_path: the scan root; ``cfg.sarif_output`` is resolved under it.
        produce_argv: OPTIONAL Phase-16 (BYO-02) live-invocation argv. When
            given (and the tool is enabled+attested), this command is run FIRST
            — it is the commercial binary that PRODUCES ``cfg.sarif_output``.
            The credential token is read at runtime from
            ``os.environ[cfg.credential_env]`` (env-var NAME only, never stored;
            Pitfall 8) and threaded into the child env under that same name —
            the token is NEVER echoed into ``notes`` / findings / stderr. When
            ``None`` (the Phase-6 pre-written-SARIF callers), nothing is invoked
            and the seam is a no-op — the pre-written SARIF is read directly,
            exactly as before this parameter existed.
        base_env: OPTIONAL base environment the live invocation runs under
            (cache-redirected scan env from the caller). Defaults to the current
            process environment. The credential (if any) is layered on top.
        sarif_from_stdout: when True, the live invocation emits its SARIF to
            STDOUT rather than to ``cfg.sarif_output`` (CR-01: Semgrep ``--sarif``
            and ggshield ``--format sarif`` both print to stdout — they take no
            ``--output`` flag in the audited argv). The captured ``inv.stdout``
            is then parsed instead of opening the file. Only meaningful when
            ``produce_argv`` is supplied; ignored otherwise. Defaults to False so
            the file-writing tools (Snyk ``--sarif-file-output``) and the Phase-6
            pre-written-SARIF callers are unchanged.

    Returns:
        An :class:`AdapterResult`. ``status='ok'`` with ``source_tool``-tagged
        findings when enabled+attested and the SARIF parses; otherwise
        ``status='unavailable'`` (binary exec-failed / SARIF absent / parse
        error) or ``status='timeout'`` (live invocation exceeded
        ``cfg.timeout_seconds``) with a ``notes`` reason. NEVER raises (D-25).
    """
    # --- gate first (D-06-06): a disabled/unattested tool NEVER runs ---------
    if not cfg.should_run:
        return AdapterResult(
            status="unavailable",
            notes=(
                f"BYO tool {cfg.name!r} not enabled or missing use-rights "
                f"attestation — skipped (default OFF, D-06-06)."
            ),
            source_adapter=_SOURCE_ADAPTER,
            source_tool=cfg.name,
            dimension=cfg.default_dimension,
        )

    sarif_path = Path(repo_path) / cfg.sarif_output

    # SARIF captured from a stdout-emitting live invocation (CR-01). Stays None
    # for the file-based path (pre-written SARIF, or a tool that writes a file).
    sarif_stdout: str | None = None

    # --- Phase-16 (BYO-02) live invocation seam ------------------------------
    # If a produce-argv is supplied, run the commercial binary FIRST to PRODUCE
    # cfg.sarif_output. Token read by env-var NAME at runtime (never stored,
    # never logged — Pitfall 8). Downstream read + parse is UNCHANGED.
    if produce_argv is not None:
        env: dict[str, str] = dict(base_env) if base_env is not None else dict(os.environ)
        if cfg.credential_env:
            token = os.environ.get(cfg.credential_env)
            if token is not None:
                # Thread the token under ITS OWN env-var name so the child tool
                # reads it the way it expects. Never placed in notes/findings.
                env[cfg.credential_env] = token

        inv = run_tool(
            produce_argv,
            env=env,
            cwd=repo_path,
            timeout_seconds=cfg.timeout_seconds,
        )

        # Gate on the run_tool structural sentinels FIRST. snyk/ggshield exit
        # NON-ZERO when they find issues (Pitfall 9) — a non-zero exit is NOT a
        # failure; the real gate is whether the SARIF parses below. Only the
        # honest sentinels short-circuit here.
        if inv.returncode == TIMED_OUT:
            return AdapterResult(
                status="timeout",
                notes=(
                    f"BYO tool {cfg.name!r}: live invocation exceeded "
                    f"{cfg.timeout_seconds}s."
                ),
                source_adapter=_SOURCE_ADAPTER,
                source_tool=cfg.name,
                dimension=cfg.default_dimension,
            )
        if inv.returncode == EXEC_FAILED:
            return AdapterResult(
                status="unavailable",
                notes=(
                    f"BYO tool {cfg.name!r}: live invocation could not be "
                    f"executed (binary missing or not runnable)."
                ),
                source_adapter=_SOURCE_ADAPTER,
                source_tool=cfg.name,
                dimension=cfg.default_dimension,
            )

        # CR-01: stdout-emitting SARIF tools (Semgrep --sarif / ggshield
        # --format sarif) print to stdout — never to cfg.sarif_output. Capture
        # the stdout for the parse below instead of opening a file that the tool
        # never wrote. The exit code (CR-02) disambiguates a real failure from a
        # missing file: a non-zero exit is NOT a failure for these tools
        # (Pitfall 9 — they exit non-zero when they FIND issues), so it is folded
        # into the notes for diagnosability rather than short-circuiting here.
        if sarif_from_stdout:
            sarif_stdout = inv.stdout

    # --- read the SARIF (from stdout, a pre-written file, or one just produced)
    if sarif_stdout is not None:
        try:
            doc = json.loads(sarif_stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            return AdapterResult(
                status="unavailable",
                notes=(
                    f"BYO tool {cfg.name!r}: live invocation emitted no parseable "
                    f"SARIF on stdout (exit {inv.returncode}): "
                    f"{type(exc).__name__}."
                ),
                source_adapter=_SOURCE_ADAPTER,
                source_tool=cfg.name,
                dimension=cfg.default_dimension,
            )
    else:
        try:
            with sarif_path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except FileNotFoundError:
            return AdapterResult(
                status="unavailable",
                notes=f"BYO tool {cfg.name!r}: SARIF output not found at {cfg.sarif_output}",
                source_adapter=_SOURCE_ADAPTER,
                source_tool=cfg.name,
                dimension=cfg.default_dimension,
            )
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(
                status="unavailable",
                notes=(
                    f"BYO tool {cfg.name!r}: could not read/parse SARIF at "
                    f"{cfg.sarif_output}: {type(exc).__name__}: {exc}"
                ),
                source_adapter=_SOURCE_ADAPTER,
                source_tool=cfg.name,
                dimension=cfg.default_dimension,
            )

    if not isinstance(doc, dict):
        return AdapterResult(
            status="unavailable",
            notes=(
                f"BYO tool {cfg.name!r}: SARIF at {cfg.sarif_output} did not load "
                f"as a mapping (got {type(doc).__name__})."
            ),
            source_adapter=_SOURCE_ADAPTER,
            source_tool=cfg.name,
            dimension=cfg.default_dimension,
        )

    # --- route through the SAME pipeline as the 8 OSS tools (no fork) -------
    try:
        findings = sarif_to_findings(
            doc,
            source_tool=cfg.name,
            default_dimension=cfg.default_dimension,
            severity_map=cfg.severity_map,  # type: ignore[arg-type]  # {level: Severity}
        )
    except Exception as exc:  # noqa: BLE001 — D-25 boundary: never raise
        return AdapterResult(
            status="unavailable",
            notes=(
                f"BYO tool {cfg.name!r}: SARIF parse failed: "
                f"{type(exc).__name__}: {exc}"
            ),
            source_adapter=_SOURCE_ADAPTER,
            source_tool=cfg.name,
            dimension=cfg.default_dimension,
        )

    return AdapterResult(
        findings=findings,
        status="ok",
        source_adapter=_SOURCE_ADAPTER,
        source_tool=cfg.name,
        dimension=cfg.default_dimension,
    )


__all__ = ["run_byo_tool"]
