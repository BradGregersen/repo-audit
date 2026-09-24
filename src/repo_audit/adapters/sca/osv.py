"""osv-scanner collection — invoke (sarif + json), parse, enrich (SCA-01/SCA-03).

``collect_osv`` is the cross-stack osv-scanner collection FUNCTION (NOT a
per-stack ``@register_adapter`` entry — A1 RESOLVED). Plan 05 wires it into
``orchestration/scan_runner.run_scan`` as a dedicated repo-wide scan step.

The finding pipeline (CONTEXT.md discretion constraint — SARIF is the SINGLE
finding source, JSON is enrichment ONLY):

    1. resolve_tool("osv-scanner", repo) — vendor/osv-scanner/osv-scanner wins
       (D-06-10). None -> status='unavailable' (osv is the floor, D-07-10).
    2. run_tool(... --format sarif ...) — the finding source.
    3. run_tool(... --format json ...) — enrichment source (Task 2 consumes it).
    4. parse the SARIF through the ONE shared parse path (FND-01) — the SARIF
       parser is the only producer of findings here; this module never builds a
       finding object itself and never opens a second parse path.
    5. extract scanner_version from the SARIF driver (for FeedProvenance, Plan 05).
    6. build_osv_enrichment(json) + apply_enrichment(findings, ...) — fold
       direct/transitive + fix version onto the SARIF findings by key.

Exit-code contract: osv exits 0 on a clean scan and 1 when it FINDS
vulnerabilities — both are successful scans. Any other exit is an error (e.g.
127: no local vulnerability database; 128: no packages found) and is reported
``unavailable`` with a bounded stderr tail, never as a clean scan — osv still
prints a valid, empty SARIF on those paths, so parsing stdout alone would turn
a dead database into a false "no vulnerabilities". A "could not load db"
warning on stderr is treated the same way even on exit 0. The run_tool
sentinels (-1 exec-failed, -2 timed-out) and an unparseable stdout also map to
unavailable/timeout. ``collect_osv`` NEVER raises across its boundary (mirrors
the AdapterResult never-raise contract): every failure becomes an OsvResult.

Pinned-mode flag note (RESEARCH Pitfall 5): the scan argv passes the offline
vulnerability flag but omits the DB-download flag — the DB is used but never
advanced/network-fetched. The persistent DB cache dir is
layered onto the env by Plan 05 (``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY``); this
function only invokes through the env it is handed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sca.enrich import (
    apply_enrichment,
    build_osv_enrichment,
)
from repo_audit.adapters.sca.refresh import _redact_tail
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

OsvStatus = Literal["ok", "unavailable", "timeout"]

# osv-scanner timeout: 120 s (matches adapter.yaml osv-scanner.timeout_ms).
_OSV_TIMEOUT_SECONDS: float = 120.0

# Bound on the stderr tail carried into OsvResult.notes (after whitespace is
# collapsed to one line).
_STDERR_TAIL_CHARS: int = 300


def _stderr_tail(text: str) -> str:
    """A bounded, single-line, secret-linted tail of a tool's stderr."""
    one_line = " ".join((text or "").split())
    return _redact_tail(one_line[-_STDERR_TAIL_CHARS:]) or "(no stderr)"


@dataclass
class OsvResult:
    """The never-raise envelope returned by :func:`collect_osv`.

    Mirrors the AdapterResult never-raise contract for the cross-stack SCA step:
    every failure mode is folded into a status + notes rather than an exception.
    """

    findings: list[Finding] = field(default_factory=list)
    status: OsvStatus = "ok"
    scanner_version: Optional[str] = None
    notes: str = ""


def _osv_argv(binary: Path, repo_path: Path, output_format: str) -> list[str]:
    """Build the osv ``scan source`` argv for a given output format.

    Pinned mode (Pitfall 5): the offline-vulnerabilities flag is present and the
    DB-download flag is omitted — uses the local DB, no network for
    vuln matching. ``--recursive`` lets osv auto-detect every supported lockfile
    under the repo (SCA-01 lockfile discovery). Read-only: ``scan source`` does
    not write into the target repo.
    """
    return [
        str(binary),
        "scan",
        "source",
        "--recursive",
        "--offline-vulnerabilities",
        "--format",
        output_format,
        str(repo_path),
    ]


def _extract_scanner_version(sarif: dict) -> Optional[str]:
    """Pull ``runs[0].tool.driver.version`` from the osv SARIF, guarding gaps."""
    try:
        runs = sarif.get("runs") or []
        driver = ((runs[0] or {}).get("tool") or {}).get("driver") or {}
        version = driver.get("version")
        return version if isinstance(version, str) else None
    except (IndexError, AttributeError, TypeError):
        return None


def collect_osv(repo_path: Path, env: dict[str, str]) -> OsvResult:
    """Run osv-scanner over ``repo_path`` and return enriched findings.

    Args:
        repo_path: the repo to scan (osv auto-detects lockfiles recursively).
        env: the child environment (cache-redirected + DB-pinned by the caller,
            Plan 05). Passed verbatim to ``run_tool``.

    Returns:
        An :class:`OsvResult`. ``status='ok'`` only when osv exits 0 (clean) or
        1 (vulnerabilities found) and its SARIF parses. ``status='unavailable'``
        when osv is not resolved, exits with any other code (e.g. 127 no local
        DB, 128 no packages), reports "could not load db", or its SARIF cannot
        be parsed (osv is the floor — the caller maps this to the whole SCA
        dimension unavailable); ``status='timeout'`` when the run exceeds the
        timeout. Never raises.
    """
    binary = resolve_tool("osv-scanner", repo_path, trusted_only=True)
    if binary is None:
        return OsvResult(
            status="unavailable",
            findings=[],
            notes="osv-scanner not found (vendor + PATH miss)",
        )

    # 1. SARIF invocation — the finding source.
    sarif_invocation = run_tool(
        _osv_argv(binary, repo_path, "sarif"),
        env=env,
        cwd=repo_path,
        timeout_seconds=_OSV_TIMEOUT_SECONDS,
    )
    if sarif_invocation.returncode == TIMED_OUT:
        return OsvResult(
            status="timeout",
            findings=[],
            notes=f"osv-scanner (sarif) exceeded {_OSV_TIMEOUT_SECONDS:.0f}s",
        )
    if sarif_invocation.returncode == EXEC_FAILED:
        return OsvResult(
            status="unavailable",
            findings=[],
            notes=f"osv-scanner could not be executed: {sarif_invocation.stderr}",
        )

    # Exit-code gate: 0 (clean) and 1 (vulns found) are successful scans;
    # anything else — e.g. 127 no local DB, 128 no packages — is an error and is
    # reported unavailable, never a clean scan. A "could not load db" warning is
    # treated the same way even on exit 0.
    rc = sarif_invocation.returncode
    if rc not in (0, 1) or "could not load db" in (sarif_invocation.stderr or "").lower():
        return OsvResult(
            status="unavailable",
            findings=[],
            notes=f"osv-scanner exited {rc}: {_stderr_tail(sarif_invocation.stderr)}",
        )

    # 2. JSON invocation — the enrichment source (direct/transitive + fix).
    json_invocation = run_tool(
        _osv_argv(binary, repo_path, "json"),
        env=env,
        cwd=repo_path,
        timeout_seconds=_OSV_TIMEOUT_SECONDS,
    )

    # 3. Parse SARIF -> findings via the SINGLE parse path (FND-01). The exit
    #    code was already gated above (only 0 and 1 reach here); an unparseable
    #    SARIF -> unavailable.
    try:
        osv_sarif = json.loads(sarif_invocation.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return OsvResult(
            status="unavailable",
            findings=[],
            notes=f"osv-scanner SARIF did not parse: {type(exc).__name__}: {exc}",
        )

    try:
        findings = sarif_to_findings(
            osv_sarif,
            source_tool="osv-scanner",
            default_dimension="security",
            severity_map={},
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return OsvResult(
            status="unavailable",
            findings=[],
            notes=f"osv SARIF parse failed: {type(exc).__name__}: {exc}",
        )

    scanner_version = _extract_scanner_version(osv_sarif)

    # 4. Fold enrichment onto the findings. Enrichment failures are non-fatal:
    #    findings still stand on their own (SARIF source); a bad JSON parse just
    #    leaves direct/fix as UNKNOWN (apply_enrichment defaults None).
    try:
        osv_json = json.loads(json_invocation.stdout)
        enrichment = build_osv_enrichment(osv_json)
    except Exception:  # noqa: BLE001 — enrichment is best-effort, never fatal
        enrichment = {}
    apply_enrichment(findings, enrichment)

    return OsvResult(
        findings=findings,
        status="ok",
        scanner_version=scanner_version,
        notes="",
    )


__all__ = ["OsvResult", "OsvStatus", "collect_osv"]
