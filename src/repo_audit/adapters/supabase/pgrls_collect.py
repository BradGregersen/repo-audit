"""pgrls collector — the flag-gated ADDITIVE RLS-01 SARIF layer (Plan 08-03).

pgrls adds tenant-scoping depth + SARIF on top of the always-on splinter floor
(Plan 02). But pgrls is a 5-week-old v0.x **Beta** (RESEARCH Pitfall 6), so it
earns its place behind an explicit ``--rls-pgrls`` flag (the gating itself is
enforced upstream in Plan 05 — this module only RUNS when the flag is set) AND a
graceful-degrade wrapper (D-08-06/07): ANY failure mode — absent binary,
timeout, exec-failure, malformed JSON, or a parser surprise from a Beta-tool
regression — degrades to ``AdapterResult(status="unavailable")`` rather than
crashing the RLS dimension. The splinter floor (Plan 02) is independent, so
RLS-01 still produces findings when pgrls degrades.

THREE-ingest-path rule (D-08-14): pgrls is the ONLY SARIF source this phase. Its
``--format sarif`` output routes through the ONE shared ``sarif_to_findings``
parse path (FND-01) with a pgrls-specific ``severity_map``. squawk (the other
Plan 08-03 collector) has NO SARIF reporter and uses a native-JSON adapter — do
NOT assume "everything is SARIF."

Severity discipline (SCH-04 cap). ``PGRLS_SEVERITY`` is the FAITHFUL level map
(error->critical, warning->major, note->minor, none->info). The shared SARIF
parser caps a faithful ``critical``/``blocker`` down to ``major`` at
``confidence="candidate"`` (SCH-04 / the binding Phase-6 DI-06-01-01 contract)
and stashes the faithful severity in ``evidence.parsed_value["faithful_severity"]``
— pgrls inherits that behaviour for free by routing through the single path.
Only Phase 17 corroboration may later promote confidence and raise severity.

Provenance (D-08-06). :func:`pgrls_version` records the exact installed pgrls
version (from dist metadata, falling back to the pyproject floor pin) so a
report can attribute a finding to a reproducible tool version.
"""
from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.enums import Severity

# pgrls per-tool SARIF level -> FAITHFUL Severity (D-06-01 shape). The shared
# parser caps a faithful critical/blocker -> major at confidence=candidate
# (SCH-04); the faithful value is preserved in parsed_value. We keep the map
# faithful here so the cap stays a single, audited parser-level behaviour.
PGRLS_SEVERITY: dict[str, Severity] = {
    "error": "critical",
    "warning": "major",
    "note": "minor",
    "none": "info",
}

# The dimension every pgrls finding lands on (SARIF carries no dimension signal;
# pgrls is an RLS/tenant-scoping security tool — D-06-05 caller-supplied default).
_PGRLS_DIMENSION = "security"

# Floor pin matching pyproject (CLAUDE.md: pgrls>=0.14.0) — the fallback when the
# dist metadata is unavailable (editable pre-build edge case, mirroring the
# package __init__ PackageNotFoundError handling).
_PGRLS_FALLBACK_VERSION = "0.14.0"

# pgrls lints a live (ephemeral) DB; 120 s matches the splinter/osv per-tool bound.
_PGRLS_TIMEOUT_SECONDS: float = 120.0


def pgrls_version() -> str:
    """Return the exact installed pgrls version for finding provenance (D-08-06).

    Reads the pinned version from the installed dist metadata; falls back to the
    pyproject floor pin when metadata is unavailable (editable pre-build edge
    case). Never raises.
    """
    try:
        return _dist_version("pgrls")
    except PackageNotFoundError:
        return _PGRLS_FALLBACK_VERSION


def collect_pgrls(
    dsn: str,
    *,
    env: dict[str, str],
    timeout_seconds: float = _PGRLS_TIMEOUT_SECONDS,
    scan_target: Path,
) -> AdapterResult:
    """Run pgrls against ``dsn`` and route its SARIF through the shared parser.

    The graceful-degrade contract (D-08-07): EVERY failure mode is folded into an
    ``AdapterResult`` rather than an exception — a Beta-tool regression never
    crashes the RLS dimension. The flag gating (``--rls-pgrls``) is enforced
    upstream in Plan 05; this function is the collection logic + the wrapper.

    Args:
        dsn: the ``postgresql://…`` connection string for the (ephemeral) DB
            that Plan 02 stood up and Plan 05 hands in.
        env: the child environment passed verbatim to ``run_tool``.
        timeout_seconds: per-call timeout for the pgrls invocation.
        scan_target: the directory used for tool resolution (vendor-then-PATH).

    Returns:
        ``AdapterResult(status="ok")`` with the parsed findings, or
        ``status="unavailable"`` (absent binary / exec-failed / malformed SARIF /
        parser surprise) or ``status="timeout"`` (timed out). Never raises.
    """
    binary = resolve_tool("pgrls", scan_target)
    if binary is None:
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes="pgrls not installed (vendor + PATH miss) — splinter floor still produces RLS findings",
            source_tool="pgrls",
            dimension=_PGRLS_DIMENSION,
        )

    invocation = run_tool(
        [str(binary), "lint", "--database-url", dsn, "--format", "sarif"],
        env=env,
        cwd=scan_target,
        timeout_seconds=timeout_seconds,
    )

    if invocation.returncode == TIMED_OUT:
        return AdapterResult(
            status="timeout",
            findings=[],
            notes=f"pgrls exceeded {timeout_seconds:.0f}s",
            source_tool="pgrls",
            dimension=_PGRLS_DIMENSION,
        )
    if invocation.returncode == EXEC_FAILED:
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=f"pgrls could not be executed: {invocation.stderr[:200]}",
            source_tool="pgrls",
            dimension=_PGRLS_DIMENSION,
        )

    # Wrap the parse in a broad guard: a Beta-tool regression (malformed SARIF,
    # a stack trace on stdout, a parser surprise — A2) must degrade to
    # unavailable, NEVER crash the dimension (D-08-07). The notes carry only a
    # bounded, redacted reason (type name + short tail), per T-08-12.
    try:
        sarif = json.loads(invocation.stdout)
        findings = sarif_to_findings(
            sarif,
            source_tool="pgrls",
            default_dimension=_PGRLS_DIMENSION,
            severity_map=PGRLS_SEVERITY,
        )
        # HARD CRIT-4 post-pass — every static finding must be verify-phrased.
        assert_verify_phrasing(findings)
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=f"pgrls degraded: {type(exc).__name__}: {str(exc)[:160]}",
            source_tool="pgrls",
            dimension=_PGRLS_DIMENSION,
        )

    return AdapterResult(
        status="ok",
        findings=findings,
        notes=f"pgrls {pgrls_version()}",
        source_tool="pgrls",
        dimension=_PGRLS_DIMENSION,
    )


__all__ = ["PGRLS_SEVERITY", "collect_pgrls", "pgrls_version"]
