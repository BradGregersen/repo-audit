"""squawk collector — RLS-02 migration-safety via native JSON (Plan 08-03).

squawk is the RLS-02 migration-safety FLOOR. It is pure static SQL-text linting
over the discovered migration files — it needs NO database connection (it never
executes the SQL), so it is independent of the ephemeral-PG infra (Plan 02).

THREE-ingest-path rule (D-08-14 / RESEARCH Pitfall 3 / A5): squawk has NO
static-analysis-interchange reporter (it emits json/tty/gcc/gitlab only), so this
module maps squawk's NATIVE ``--reporter=json`` output with a bespoke per-tool
adapter — it does NOT route through the shared interchange parse path that pgrls
uses (pgrls is the only such source this phase). Mirrors the Phase 7
``osv``/``grype`` native-JSON-fold precedent: run_tool -> json.loads -> Finding.

Severity discipline (SCH-04 cap). squawk reports a ``level`` per violation
(``Warning`` / ``Error``). :data:`_SQUAWK_LEVEL_TO_SEVERITY` is the pinned,
deterministic table: ``Warning -> minor``, ``Error -> major``. ``major`` is the
ceiling — squawk findings are ``confidence="candidate"`` and SCH-04 forbids
``candidate`` + ``{critical, blocker}``. Only Phase 17 corroboration may later
promote.

Dimension routing (the D-08 Claude's-discretion item — pinned here).
:data:`_SQUAWK_RULE_TO_DIMENSION` routes squawk's rules:

  * **correctness** — destructive / lock-taking / non-rerunnable migration rules
    (``ban-drop-column``, ``ban-drop-table``, ``ban-drop-not-null``,
    ``require-concurrent-index-creation``, ``prefer-robust-stmts``,
    ``adding-required-field``, …). A destructive or lock-taking migration is a
    correctness / data-safety smell, not a "security" finding per se: it risks
    breaking clients, data loss, or a production-locking deploy. The DEFAULT for
    any unrecognised rule is ``correctness`` (squawk's whole remit is
    migration-safety = correctness).
  * **security** — any access-control-relevant rule (e.g. a future
    ``disallowed-unique-constraint`` that touches RLS surface, or a policy/grant
    rule). squawk ships few such rules today; the table is the seam for them.

Rationale (pinned, auditable): the planner chose ``correctness`` as the squawk
default because squawk lints migration SAFETY (the 4th dimension — correctness &
data/privacy), distinct from splinter/pgrls which lint RLS access-control
(security). This keeps the report's dimension routing faithful to what each tool
actually checks.

Verify-phrasing (CRIT-4). Static SQL-text linting proves a migration's *shape*,
never that production safely applied it. The report-visible recommendation is
verify-phrased and NEVER echoes the raw squawk ``message`` / ``help`` (which
could carry runtime-certainty words) into report prose — the raw entry lives in
``evidence.parsed_value`` (exempt from the tripwire). Every batch is routed
through :func:`assert_verify_phrasing` before return.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.enums import Dimension, Severity
from repo_audit.schema.finding import Evidence, Finding

# squawk level -> mapped Severity. ``major`` is the ceiling: squawk findings are
# confidence="candidate" and SCH-04 forbids candidate + {critical, blocker}.
_SQUAWK_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "Error": "major",
    "Warning": "minor",
}

# Default severity when squawk emits an unrecognised level string.
_DEFAULT_SEVERITY: Severity = "minor"

# squawk rule -> 7-dimension routing (the D-08 discretion item, pinned). The
# DEFAULT is "correctness" — squawk's whole remit is migration safety. Only an
# access-control-relevant rule routes to "security".
_SQUAWK_RULE_TO_DIMENSION: dict[str, Dimension] = {
    # Destructive / lock-taking / non-rerunnable migration rules -> correctness.
    "ban-drop-column": "correctness",
    "ban-drop-table": "correctness",
    "ban-drop-database": "correctness",
    "ban-drop-not-null": "correctness",
    "ban-char-field": "correctness",
    "ban-truncate-cascade": "correctness",
    "require-concurrent-index-creation": "correctness",
    "require-concurrent-index-deletion": "correctness",
    "require-timeout-settings": "correctness",
    "prefer-robust-stmts": "correctness",
    "prefer-bigint-over-int": "correctness",
    "prefer-bigint-over-smallint": "correctness",
    "prefer-identity": "correctness",
    "prefer-text-field": "correctness",
    "adding-required-field": "correctness",
    "adding-field-with-default": "correctness",
    "adding-not-nullable-field": "correctness",
    "adding-serial-primary-key-field": "correctness",
    "changing-column-type": "correctness",
    "constraint-missing-not-valid": "correctness",
    "renaming-column": "correctness",
    "renaming-table": "correctness",
    "transaction-nesting": "correctness",
    # Access-control-relevant rules -> security (seam for future squawk rules).
    "disallowed-unique-constraint": "security",
}

# squawk's whole remit is migration SAFETY = correctness; default unrecognised
# rules to correctness rather than inventing a security signal.
_DEFAULT_DIMENSION: Dimension = "correctness"

# squawk text-lints the discovered SQL files; 60 s is generous for static parsing.
_SQUAWK_TIMEOUT_SECONDS: float = 60.0


def _severity_for(level: Any) -> Severity:
    """Map a squawk ``level`` string to a Severity (deterministic, capped)."""
    return _SQUAWK_LEVEL_TO_SEVERITY.get(str(level), _DEFAULT_SEVERITY)


def _dimension_for(rule_name: Any) -> Dimension:
    """Map a squawk ``rule_name`` to a 7-dimension value (default correctness)."""
    return _SQUAWK_RULE_TO_DIMENSION.get(str(rule_name), _DEFAULT_DIMENSION)


def _verify_phrased_recommendation(entry: dict[str, Any]) -> str:
    """Build a CRIT-4-clean recommendation for a squawk violation.

    Deliberately does NOT echo the raw ``message`` / ``help`` (which could carry
    runtime-certainty words) into report prose. Uses the rule name + file:line
    and a "verify" caveat so the message stays clean regardless of the entry's
    wording. The raw entry is preserved in ``parsed_value`` (tripwire-exempt).
    """
    rule = str(entry.get("rule_name", "")).strip() or "unknown_rule"
    file = str(entry.get("file", "")).strip() or "<unknown file>"
    line = entry.get("line")
    where = f"{file}:{line}" if line is not None else file
    return (
        f"squawk '{rule}' flagged a migration-safety concern at {where}. "
        "This is a static SQL-text lint of the migration's intended shape, not "
        "proof of how it applied in production. Review the migration and verify "
        "its safety (locking, rerunnability, data impact) before deploying."
    )


def map_squawk_json(payload: dict[str, Any] | list[Any]) -> list[Finding]:
    """Map squawk ``--reporter=json`` violations to static/candidate Findings.

    Deterministic, DB-free. squawk's JSON is a flat list of violation entries
    (``file``, ``line``, ``column``, ``level``, ``message``, ``help``,
    ``rule_name``, …). For each entry:

      * ``rule_id = entry["rule_name"]``
      * ``severity`` from :data:`_SQUAWK_LEVEL_TO_SEVERITY` (capped at major)
      * ``dimension`` from :data:`_SQUAWK_RULE_TO_DIMENSION` (default correctness)
      * ``confidence="candidate"``, ``evidence_type="static"``
      * a verify-phrased ``recommendation`` (NEVER enforced/secure/protected)
      * ``file``/``line`` carried onto the Finding + ``evidence.line_range``
      * the full raw entry in ``evidence.parsed_value``

    Calls :func:`assert_verify_phrasing` on the batch before returning (CRIT-4).

    Args:
        payload: squawk's parsed JSON (a list of entries; a dict wrapping a
            ``violations`` list is also tolerated).

    Returns:
        One :class:`Finding` per violation.
    """
    entries = _entries_from_payload(payload)

    findings: list[Finding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rule_name = str(entry.get("rule_name", "")).strip()
        line = entry.get("line")
        line_int = line if isinstance(line, int) else None
        file = entry.get("file")
        file_str = str(file) if file is not None else None

        evidence = Evidence(
            tool="squawk",
            # The raw entry is preserved here (exempt from the tripwire); never
            # echoed into report prose.
            parsed_value=dict(entry),
            line_range=(line_int, line_int) if line_int is not None else None,
        )

        findings.append(
            Finding(
                dimension=_dimension_for(rule_name),
                severity=_severity_for(entry.get("level")),
                file=file_str,
                line=line_int,
                evidence=evidence,
                evidence_type="static",
                confidence="candidate",
                recommendation=_verify_phrased_recommendation(entry),
                source_tool="squawk",
                source_collector="supabase-migration-safety",
                rule_id=rule_name,
            )
        )

    # HARD CRIT-4 post-pass before returning.
    assert_verify_phrasing(findings)
    return findings


def _entries_from_payload(payload: dict[str, Any] | list[Any]) -> list[Any]:
    """Normalise squawk JSON to a flat list of violation entries.

    squawk ``--reporter=json`` emits a flat list. A dict wrapper carrying a
    ``violations`` (or ``results``) list is tolerated defensively so a minor
    reporter-shape change does not crash the mapper.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("violations", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def collect_squawk(
    sql_files: list[Path],
    *,
    env: dict[str, str],
    timeout_seconds: float = _SQUAWK_TIMEOUT_SECONDS,
    scan_target: Path,
) -> AdapterResult:
    """Run squawk over the discovered SQL files and map its native JSON.

    squawk text-lints the SAME discovered SQL files that Plan 02's discovery
    returns (Plan 05 passes them in). It NEVER opens a DB connection — squawk is
    pure static SQL-text linting. Every failure mode degrades to an
    ``AdapterResult`` rather than raising.

    Args:
        sql_files: the migration SQL files to lint (from Plan 02 discovery).
        env: the child environment passed verbatim to ``run_tool``.
        timeout_seconds: per-call timeout for the squawk invocation.
        scan_target: the directory used for tool resolution (vendor-then-PATH).

    Returns:
        ``AdapterResult(status="ok")`` with the mapped findings, or
        ``status="unavailable"`` (absent binary / no SQL files / exec-failed /
        malformed JSON) or ``status="timeout"``. Never raises.
    """
    if not sql_files:
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes="no SQL files discovered — squawk has nothing to lint",
            source_tool="squawk",
            dimension=_DEFAULT_DIMENSION,
        )

    binary = resolve_tool("squawk", scan_target, trusted_only=True)
    if binary is None:
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes="squawk not installed (vendor + PATH miss)",
            source_tool="squawk",
            dimension=_DEFAULT_DIMENSION,
        )

    invocation = run_tool(
        [str(binary), "--reporter=json", *[str(p) for p in sql_files]],
        env=env,
        cwd=scan_target,
        timeout_seconds=timeout_seconds,
    )

    if invocation.returncode == TIMED_OUT:
        return AdapterResult(
            status="timeout",
            findings=[],
            notes=f"squawk exceeded {timeout_seconds:.0f}s",
            source_tool="squawk",
            dimension=_DEFAULT_DIMENSION,
        )
    if invocation.returncode == EXEC_FAILED:
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=f"squawk could not be executed: {invocation.stderr[:200]}",
            source_tool="squawk",
            dimension=_DEFAULT_DIMENSION,
        )

    # squawk exits NON-ZERO when it finds violations — that is squawk's normal
    # "issues detected" signal, NOT a failure. Gate on whether stdout parses.
    try:
        payload = json.loads(invocation.stdout)
        findings = map_squawk_json(payload)
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=f"squawk JSON did not parse/map: {type(exc).__name__}: {str(exc)[:160]}",
            source_tool="squawk",
            dimension=_DEFAULT_DIMENSION,
        )

    return AdapterResult(
        status="ok",
        findings=findings,
        notes="",
        source_tool="squawk",
        dimension=_DEFAULT_DIMENSION,
    )


__all__ = [
    "_SQUAWK_LEVEL_TO_SEVERITY",
    "_SQUAWK_RULE_TO_DIMENSION",
    "collect_squawk",
    "map_squawk_json",
]
