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

Plan 10-03 ADDS ``run_sast`` / ``collect_semgrep`` to this package.
"""
from __future__ import annotations

from repo_audit.adapters.sast.owasp import annotate_owasp
from repo_audit.adapters.sast.rulesets import select_packs

# noise.apply_noise_floor (SAST-02) and anon.drop_anon_key_secrets (SAST-03)
# land in Task 2 of this plan and are appended to the imports + __all__ there;
# the gated Wave-0 test modules import those submodules directly
# (sast.noise / sast.anon), so the package import stays valid in between.
__all__ = [
    "select_packs",
    "annotate_owasp",
]
