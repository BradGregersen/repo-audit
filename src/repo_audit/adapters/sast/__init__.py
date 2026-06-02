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

Plan 10-03 ADDS the ``SastResult`` envelope + ``collect_semgrep`` collector to
this package (``run_sast`` — the registered scan step — lands in Plan 10-04).

``SastResult`` mirrors ``sca/osv.py::OsvResult`` field-for-field: the never-raise
envelope every cross-stack SAST collection returns, folding each failure mode
into a ``status`` + ``notes`` rather than an exception.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from repo_audit.adapters.sast.anon import drop_anon_key_secrets
from repo_audit.adapters.sast.noise import apply_noise_floor
from repo_audit.adapters.sast.owasp import annotate_owasp
from repo_audit.adapters.sast.rulesets import select_packs
from repo_audit.schema.finding import Finding

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


# Imported AFTER SastResult is defined (semgrep.py imports SastResult from here)
# so the re-export does not create an import cycle at package load.
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
    "collect_semgrep",
    "run_semgrep",
]
