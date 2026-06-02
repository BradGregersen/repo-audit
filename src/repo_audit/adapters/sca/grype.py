"""grype collection — the SECOND SCA source for corroboration (SCA-02).

``collect_grype`` is the cross-stack grype collection FUNCTION (NOT a per-stack
``@register_adapter`` entry — same A1 resolution as ``collect_osv``). Plan 05
wires it into ``orchestration/scan_runner.run_scan`` alongside ``collect_osv``,
and ``corroborate`` (this plan) unions the two findings sets.

The finding pipeline mirrors ``collect_osv`` exactly — SARIF is the SINGLE
finding source (FND-01 / CONTEXT.md discretion constraint), invoked through the
ONE shared parse path; grype's native JSON is consulted ONLY to recover the
canonical ``(cve, package, version)`` identity the SARIF cannot carry on its own:

    1. resolve_tool("grype", repo) — vendor/grype/grype wins (D-06-10). None ->
       status='unavailable'. grype is OPTIONAL (D-07-10): the caller continues
       osv-only with no corroboration bump when grype is absent.
    2. run_tool(... -o sarif ...) — the finding source (the ONE parse path).
    3. run_tool(... -o json ...) — the GHSA->CVE recovery source. grype's SARIF
       carries the GHSA (primary id) but NOT the bare CVE; the CVE lives in the
       JSON ``matches[].relatedVulnerabilities[].id`` (PROVENANCE.md A5). We
       build a ``GHSA -> CVE`` map from the JSON and use it to stamp the bare CVE
       onto each finding so its corroboration key matches osv's CVE-keyed finding.
    4. parse the SARIF through ``sarif_to_findings`` (source_tool="grype").
    5. RE-EXTRACT identity (RESEARCH Pitfall 2): grype's SARIF ``ruleId`` is the
       COMPOSITE ``{vulnID}-{pkg}`` (e.g. ``GHSA-2xpw-w6gg-jr37-urllib3``), so
       ``finding.rule_id`` is NOT the bare CVE and ``enrichment_key_for`` would
       mis-key it. We recover the bare CVE (via the JSON GHSA->CVE map keyed on
       the composite ruleId's GHSA prefix), the package, and the version from the
       SARIF ``message.text`` / ``rules.properties.purls``, and stamp them into
       ``evidence.parsed_value`` so ``enrichment_key_for`` yields the SAME
       ``(cve, pkg, version)`` osv produces. ``rule_id`` is left untouched.
    6. extract scanner_version + db_snapshot_date (for FeedProvenance, Plan 05).

grype exits NON-ZERO when it finds vulnerabilities — that is grype's normal
"vulns detected" signal, NOT a failure. Only the run_tool sentinels (-1
exec-failed, -2 timed-out) and an unparseable SARIF map to unavailable/timeout.
``collect_grype`` NEVER raises across its boundary — every failure becomes a
GrypeResult (mirrors the OsvResult never-raise contract).

Pinned-mode note (RESEARCH Pitfall 5): the env carries
``GRYPE_DB_AUTO_UPDATE=false`` so grype uses its local DB without a network
auto-update; the persistent DB cache dir (``GRYPE_DB_CACHE_DIR``) is layered onto
the env by Plan 05 — this function only invokes through the env it is handed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sca.enrich import normalize_cve, normalize_pkg
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

GrypeStatus = Literal["ok", "unavailable", "timeout"]

# grype timeout: 120 s (matches the osv-scanner per-call bound; grype scans the
# same lockfile surface and should be comparably fast against a local DB).
_GRYPE_TIMEOUT_SECONDS: float = 120.0

# grype's SARIF message.text shape (PROVENANCE.md / recorded fixture):
#   "A high vulnerability in python package: urllib3, version 1.23.0 was found
#    at: /requirements.txt"
# The bare package + version live in the "package: <name>, version: <version>"
# clause. Anchored + bounded (T-07-10): no catastrophic backtracking on
# attacker-controlled message text — both captures are negated-char classes.
_PKG_VERSION_RE = re.compile(
    r"package:\s*(?P<name>[^,]+),\s*version\s*(?P<version>[^\s]+)"
)


@dataclass
class GrypeResult:
    """The never-raise envelope returned by :func:`collect_grype`.

    Mirrors :class:`OsvResult` so the caller treats both SCA sources uniformly.
    ``db_snapshot_date`` is the grype DB ``built`` timestamp (FeedProvenance,
    Plan 05); ``advisory_count`` is intentionally absent (None for grype, A3).
    """

    findings: list[Finding] = field(default_factory=list)
    status: GrypeStatus = "ok"
    scanner_version: Optional[str] = None
    db_snapshot_date: Optional[str] = None
    notes: str = ""


def _grype_argv(binary: Path, repo_path: Path, output_format: str) -> list[str]:
    """Build the grype ``dir:<repo>`` argv for a given output format.

    The ``dir:`` target is a single ``list[str]`` element — never shell
    interpolated (T-07-09); ``run_tool`` enforces ``shell=False``. Read-only:
    grype scans the directory, it does not write into the target repo.
    """
    return [str(binary), f"dir:{repo_path}", "-o", output_format]


def _build_ghsa_to_cve(grype_json: dict[str, Any]) -> dict[str, str]:
    """Map each grype primary vuln id (GHSA) to its bare CVE alias.

    grype's PRIMARY id is the GHSA; the CVE lives in
    ``matches[].relatedVulnerabilities[].id`` (PROVENANCE.md A5). This map lets
    the SARIF re-extraction recover the CVE that osv keys on. When a match has no
    related CVE the GHSA simply does not appear (the finding then keys on its
    GHSA — still surfaced, just not corroboration-joined to a CVE-only osv hit).
    """
    mapping: dict[str, str] = {}
    for match in grype_json.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        primary = vuln.get("id")
        if not isinstance(primary, str):
            continue
        for related in match.get("relatedVulnerabilities") or []:
            if not isinstance(related, dict):
                continue
            rid = related.get("id")
            if isinstance(rid, str) and rid.upper().startswith("CVE-"):
                mapping[primary] = rid
                break
    return mapping


def _ghsa_from_composite(composite_rule_id: str, package: str) -> str:
    """Recover the bare vuln id (GHSA) from grype's composite ``{vulnID}-{pkg}``.

    The composite ruleId is ``{vulnID}-{packageName}`` (Pitfall 2), e.g.
    ``GHSA-2xpw-w6gg-jr37-urllib3``. With the package name known (re-extracted
    from the message text) we strip the trailing ``-{package}`` to recover the
    bare vuln id. Falls back to the whole ruleId when the suffix does not match.
    """
    suffix = f"-{package}"
    if package and composite_rule_id.endswith(suffix):
        return composite_rule_id[: -len(suffix)]
    return composite_rule_id


def _restamp_grype_identity(
    findings: list[Finding], ghsa_to_cve: dict[str, str]
) -> None:
    """Stamp the bare ``cve``/``package``/``version`` onto each grype finding.

    RESEARCH Pitfall 2: grype's SARIF ``ruleId`` is the composite
    ``{vulnID}-{pkg}``, so ``enrichment_key_for`` (which reads ``rule_id`` as the
    CVE for osv) would mis-key a grype finding. We re-extract the canonical
    identity from the SARIF message text (package + version) and the JSON
    GHSA->CVE map (the bare CVE), then write them into ``evidence.parsed_value``
    so the SHARED ``enrichment_key_for`` yields the SAME ``(cve, pkg, version)``
    osv produces. ``rule_id`` is left untouched (a grep test may pin it).

    When no CVE alias exists for the finding's GHSA, the GHSA itself is stamped
    as the keyable id — the finding still surfaces (D-07-10), it simply will not
    corroboration-join to a CVE-only osv finding.
    """
    for finding in findings:
        message = finding.evidence.output_snippet or ""
        match = _PKG_VERSION_RE.search(message)
        package = normalize_pkg(match.group("name")) if match else ""
        version = match.group("version").strip() if match else ""

        ghsa = _ghsa_from_composite(finding.rule_id or "", package)
        cve = ghsa_to_cve.get(ghsa, ghsa)

        finding.evidence.parsed_value["cve"] = normalize_cve(cve)
        finding.evidence.parsed_value["package"] = package
        finding.evidence.parsed_value["version"] = version


def _extract_scanner_version(sarif: dict) -> Optional[str]:
    """Pull ``runs[0].tool.driver.version`` from the grype SARIF, guarding gaps."""
    try:
        runs = sarif.get("runs") or []
        driver = ((runs[0] or {}).get("tool") or {}).get("driver") or {}
        version = driver.get("version")
        return version if isinstance(version, str) else None
    except (IndexError, AttributeError, TypeError):
        return None


def _extract_db_snapshot_date(grype_json: dict[str, Any]) -> Optional[str]:
    """Pull ``descriptor.db.status.built`` (the DB snapshot date) from grype JSON.

    PROVENANCE.md A3: ``built`` is the cleanly machine-readable DB snapshot
    timestamp for FeedProvenance (advisory_count stays None). Guards every gap.
    """
    try:
        descriptor = grype_json.get("descriptor") or {}
        db = descriptor.get("db") or {}
        status = db.get("status") or {}
        built = status.get("built")
        return built if isinstance(built, str) else None
    except (AttributeError, TypeError):
        return None


def collect_grype(repo_path: Path, env: dict[str, str]) -> GrypeResult:
    """Run grype over ``repo_path`` and return corroboration-keyable findings.

    Args:
        repo_path: the repo to scan (grype's ``dir:`` target).
        env: the child environment (DB-pinned by the caller, Plan 05). Passed
            verbatim to ``run_tool``; carries ``GRYPE_DB_AUTO_UPDATE=false``.

    Returns:
        A :class:`GrypeResult`. ``status='unavailable'`` when grype is not
        resolved or its SARIF cannot be parsed (grype is OPTIONAL — the caller
        continues osv-only, D-07-10); ``status='timeout'`` on a timed-out run.
        Never raises.
    """
    binary = resolve_tool("grype", repo_path)
    if binary is None:
        return GrypeResult(
            status="unavailable",
            findings=[],
            notes="grype not found (vendor + PATH miss) — osv-only, no corroboration",
        )

    # Ensure the no-network pin is present without mutating the caller's dict.
    child_env = dict(env)
    child_env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")

    # 1. SARIF invocation — the finding source.
    sarif_invocation = run_tool(
        _grype_argv(binary, repo_path, "sarif"),
        env=child_env,
        cwd=repo_path,
        timeout_seconds=_GRYPE_TIMEOUT_SECONDS,
    )
    if sarif_invocation.returncode == TIMED_OUT:
        return GrypeResult(
            status="timeout",
            findings=[],
            notes=f"grype (sarif) exceeded {_GRYPE_TIMEOUT_SECONDS:.0f}s",
        )
    if sarif_invocation.returncode == EXEC_FAILED:
        return GrypeResult(
            status="unavailable",
            findings=[],
            notes=f"grype could not be executed: {sarif_invocation.stderr}",
        )

    # 2. JSON invocation — the GHSA->CVE recovery + FeedProvenance source.
    json_invocation = run_tool(
        _grype_argv(binary, repo_path, "json"),
        env=child_env,
        cwd=repo_path,
        timeout_seconds=_GRYPE_TIMEOUT_SECONDS,
    )

    # 3. Parse SARIF -> findings via the SINGLE parse path (FND-01). grype exits
    #    non-zero when it finds vulns, so we gate on whether stdout parses, not
    #    on returncode. An unparseable SARIF -> unavailable.
    try:
        grype_sarif = json.loads(sarif_invocation.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return GrypeResult(
            status="unavailable",
            findings=[],
            notes=f"grype SARIF did not parse: {type(exc).__name__}: {exc}",
        )

    try:
        findings = sarif_to_findings(
            grype_sarif,
            source_tool="grype",
            default_dimension="security",
            severity_map={},
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return GrypeResult(
            status="unavailable",
            findings=[],
            notes=f"grype SARIF parse failed: {type(exc).__name__}: {exc}",
        )

    # 4. Re-extract the canonical identity (Pitfall 2) using the JSON GHSA->CVE
    #    map. A bad JSON parse just leaves the GHSA as the keyable id (the CVE
    #    join is best-effort; the finding still surfaces).
    db_snapshot_date: Optional[str] = None
    try:
        grype_json = json.loads(json_invocation.stdout)
        ghsa_to_cve = _build_ghsa_to_cve(grype_json)
        db_snapshot_date = _extract_db_snapshot_date(grype_json)
    except Exception:  # noqa: BLE001 — identity recovery is best-effort
        ghsa_to_cve = {}
    _restamp_grype_identity(findings, ghsa_to_cve)

    scanner_version = _extract_scanner_version(grype_sarif)

    return GrypeResult(
        findings=findings,
        status="ok",
        scanner_version=scanner_version,
        db_snapshot_date=db_snapshot_date,
        notes="",
    )


__all__ = ["GrypeResult", "GrypeStatus", "collect_grype"]
