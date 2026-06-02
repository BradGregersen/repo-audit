"""Cross-stack SAST (Semgrep) adapter package (Phase 10).

Like ``adapters/sca`` and ``adapters/mobile``, this package does NOT call
``@register_adapter``. SAST is CROSS-STACK: a single Semgrep run scans the repo
with the ruleset packs selected for the detected stacks (Plan 10-02
:func:`rulesets.select_packs`), and Plan 10-03 wires
``orchestration/scan_runner`` to invoke it as a dedicated scan step alongside
``run_sca`` / ``run_supabase`` / ``run_mobile`` — NOT as a per-stack adapter.

This plan (10-02) ships the four PURE deterministic transform helpers — no
subprocess, no Semgrep invocation — so they are fully unit-testable against the
Wave-0 fixtures before Plan 10-03's collector wires them together:

    * :func:`rulesets.select_packs` — detected stacks → ``p/...`` registry packs
      (always ``p/owasp-top-ten`` + ``p/secrets``; ``+p/typescript`` for TS;
      ``+p/react`` for expo/react-native), deduped + stable order.
    * :func:`noise.apply_noise_floor` — SAST-02 / CRIT-2 path-exclude + severity
      floor, overridable via an ``.repo-audit.yaml`` ``sast`` block.
    * :func:`anon.drop_anon_key_secrets` — SAST-03 anon-allowlist drop + boundary
      redaction + RLS cross-link (reuses ``supabase.footguns`` verbatim).
    * :func:`owasp.annotate_owasp` — count-invariant OWASP/CWE tag extraction
      from ``rule.properties.tags`` (FND-01: SARIF stays the single source).

Plan 10-03 ADDED the ``SastResult`` envelope + ``collect_semgrep`` collector to
this package. Plan 10-04 ADDS :func:`run_sast` — the cross-stack ``scan_runner``
STEP (NOT a per-stack ``@register_adapter`` entry; mirrors ``run_sca`` /
``run_supabase`` / ``run_mobile``) — plus its :class:`SastScanResult` envelope.
``run_sast`` selects the ruleset packs from the stack detection, runs
``collect_semgrep``, stamps a D-10-02 ``FeedProvenance`` entry (via
``provenance.build_sast_provenance``), and returns the merged findings + status +
notes + the provenance stamp for ``orchestration/scan_runner`` to fold.

``SastResult`` mirrors ``sca/osv.py::OsvResult`` field-for-field: the never-raise
envelope every cross-stack SAST COLLECTION returns. ``SastScanResult`` mirrors
``sca/__init__.py::ScaScanResult``: the never-raise envelope the cross-stack SAST
STEP returns to ``scan_runner`` (findings + feed_provenance + status + notes).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from repo_audit.adapters.sast.anon import drop_anon_key_secrets
from repo_audit.adapters.sast.noise import apply_noise_floor
from repo_audit.adapters.sast.owasp import annotate_owasp
from repo_audit.adapters.sast.rulesets import select_packs
from repo_audit.schema.finding import Finding
from repo_audit.schema.report import FeedProvenance

if TYPE_CHECKING:
    from repo_audit.schema.detection import DetectionResult

SastStatus = Literal["ok", "unavailable", "timeout"]


@dataclass
class SastResult:
    """The never-raise envelope returned by :func:`semgrep.collect_semgrep`.

    Mirrors ``OsvResult`` field-for-field (the cross-stack SCA precedent): every
    failure mode — absent binary, exec failure, timeout, unparseable SARIF — is
    folded into ``status`` + ``notes`` rather than raised. ``status='ok'`` carries
    the de-noised security findings; ``scanner_version`` is the SARIF driver
    version (FeedProvenance, Plan 04).
    """

    findings: list[Finding] = field(default_factory=list)
    status: SastStatus = "ok"
    scanner_version: Optional[str] = None
    notes: str = ""


@dataclass
class SastScanResult:
    """The never-raise envelope returned by :func:`run_sast` (the cross-stack STEP).

    Mirrors ``sca/__init__.py::ScaScanResult`` field-for-field (the cross-stack
    precedent). ``scan_runner`` reads ``findings`` into the merged finding set and
    EXTENDS ``ReportMeta.feed_provenance`` with ``feed_provenance``; ``status`` +
    ``notes`` fold into the scope ledger + the partial flag (SAFE-08). Defaults to
    an empty ``ok`` so a ``--no-sast`` skip / an absent-semgrep run is a benign,
    findingless, stampless result.
    """

    findings: list[Finding] = field(default_factory=list)
    feed_provenance: list[FeedProvenance] = field(default_factory=list)
    status: SastStatus = "ok"
    notes: str = ""


def run_sast(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    detection: "DetectionResult",
) -> SastScanResult:
    """Run the cross-stack SAST step: select packs → Semgrep → de-noised findings.

    This is the cross-stack SAST scan STEP (NOT a per-stack
    ``@register_adapter`` — SAST runs ONCE per repo regardless of the detected
    stacks, like ``run_sca`` / ``run_supabase`` / ``run_mobile``). Plan 10-04
    wires it into ``orchestration/scan_runner.run_scan`` as a dedicated step.

    Composes the whole SAST pipeline:
    ``select_packs(detection)`` → ``collect_semgrep(repo, base_env, packs=...)`` →
    ``build_sast_provenance(result, queried_at=now)``.

    Args:
        repo_path: the repo to scan (Semgrep recurses from here).
        base_env: the base child env (typically a ``build_scan_env`` tempdir env);
            ``collect_semgrep`` layers its no-egress Semgrep vars on top.
        detection: the stack-detection result driving pack selection (always
            ``p/owasp-top-ten`` + ``p/secrets``; ``+p/typescript`` / ``+p/react``
            per detected stack).

    Returns:
        A :class:`SastScanResult`; NEVER raises (``collect_semgrep`` never raises;
        ``select_packs`` is pure). On a successful run it carries the de-noised
        security findings plus a single D-10-02 ``FeedProvenance`` stamp
        (``db_snapshot_date=None`` runtime-fetch); on unavailable/timeout it
        carries no findings and no stamp, with the failure folded into ``notes``.
    """
    packs = select_packs(detection)
    result = collect_semgrep(repo_path, base_env, packs=packs)
    prov = build_sast_provenance(result, queried_at=datetime.now())
    notes = result.notes or (
        f"semgrep packs: {', '.join(packs)}" if result.status == "ok" else ""
    )
    return SastScanResult(
        findings=result.findings,
        feed_provenance=prov,
        status=result.status,
        notes=notes,
    )


# Imported AFTER SastResult is defined (semgrep.py imports SastResult from here,
# and provenance.py imports SastResult from semgrep) so the re-export + the
# run_sast composition do not create an import cycle at package load.
from repo_audit.adapters.sast.provenance import build_sast_provenance  # noqa: E402
from repo_audit.adapters.sast.semgrep import (  # noqa: E402
    collect_semgrep,
    run_semgrep,
)

__all__ = [
    "select_packs",
    "apply_noise_floor",
    "drop_anon_key_secrets",
    "annotate_owasp",
    "SastResult",
    "SastStatus",
    "SastScanResult",
    "run_sast",
    "build_sast_provenance",
    "collect_semgrep",
    "run_semgrep",
]
