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
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.byo.config import ByoToolConfig
from repo_audit.adapters.sarif import sarif_to_findings

_SOURCE_ADAPTER = "byo"


def run_byo_tool(cfg: ByoToolConfig, repo_path: str | Path) -> AdapterResult:
    """Run a single BYO opt-in tool: gate on attestation, then route its SARIF.

    Args:
        cfg: the validated per-tool opt-in config (the attestation gate).
        repo_path: the scan root; ``cfg.sarif_output`` is resolved under it.

    Returns:
        An :class:`AdapterResult`. ``status='ok'`` with ``source_tool``-tagged
        findings when enabled+attested and the SARIF parses; otherwise
        ``status='unavailable'`` with a ``notes`` reason. NEVER raises (D-25).
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

    # --- read the pre-written SARIF (Phase 16 inserts live invocation here) --
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
