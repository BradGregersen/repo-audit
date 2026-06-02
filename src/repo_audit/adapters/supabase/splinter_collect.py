"""splinter row→Finding mapper + ``run_splinter`` (Plan 08-02).

splinter is the authoritative, always-on Supabase RLS/security lint floor
(D-08-06). It is NOT a SARIF tool (D-08-14): executing the vendored
``splinter.sql`` against a live (ephemeral) database returns a uniform
**10-column** row set —
``name, title, level, facing, categories, description, detail, remediation,
metadata, cache_key`` — one row per lint hit.

This module owns two thin, separable pieces:

  * :func:`map_splinter_rows` — the deterministic, DB-free row→:class:`Finding`
    mapper. Unit-testable on the frozen fixture. Every mapped Finding is
    ``evidence_type="static"`` + ``confidence="candidate"`` (D-08-17), verify-
    phrased (CRIT-4), and routed through :func:`assert_verify_phrasing` before
    return.
  * :func:`run_splinter` — reads the vendored SQL and executes it through
    psycopg3 against a DSN, returning raw rows. Kept thin so the mapper stays
    DB-free and unit-testable.

**Severity discipline (SCH-04 cap).** splinter's ``level`` is INFO/WARN/ERROR.
A faithful ERROR would be ``critical``, but splinter findings are
``confidence="candidate"`` and SCH-04 (Phase-1 Decision-B / the binding Phase-6
DI-06-01-01 contract) forbids ``candidate`` + ``{critical, blocker}``. So ERROR
is CAPPED at ``major`` and the faithful severity is stashed in
``evidence.parsed_value["faithful_severity"]`` (the Phase 6 SARIF-cap precedent).
Only Phase 17 corroboration may later promote confidence and raise severity.

**Dimension.** ``categories`` carries SECURITY / PERFORMANCE; SECURITY→security,
PERFORMANCE→quality, default "security" when ambiguous (the floor is a security
lint).

**Verify-phrasing.** Static introspection of a FRESH ephemeral DB proves a
repo's *intended* policy shape, never that production enforces it. So the
report-visible prose NEVER says enforced/secure/protected — the recommendation
is phrased as "… present; verify enforcement at runtime." The raw splinter
``detail``/``description`` (which CAN contain such words) lives only in
``evidence.parsed_value``, which the tripwire exempts.
"""
from __future__ import annotations

import importlib.resources
from typing import Any

from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.schema.enums import Dimension, Severity
from repo_audit.schema.finding import Evidence, Finding

# splinter level → mapped Severity. ERROR is CAPPED at "major" because splinter
# findings are confidence="candidate" and SCH-04 forbids candidate+critical/
# blocker; the faithful severity is preserved in parsed_value (see below).
_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "ERROR": "major",
    "WARN": "minor",
    "INFO": "info",
}

# The severity a faithful (uncapped) mapping WOULD have assigned — stashed in
# parsed_value["faithful_severity"] so the SCH-04 cap is auditable and Phase 17
# corroboration can promote back up.
_LEVEL_TO_FAITHFUL_SEVERITY: dict[str, Severity] = {
    "ERROR": "critical",
    "WARN": "minor",
    "INFO": "info",
}

# splinter category → 7-dimension taxonomy. SECURITY is the floor's reason for
# being; PERFORMANCE rolls into "quality". Default "security" when ambiguous.
_CATEGORY_TO_DIMENSION: dict[str, Dimension] = {
    "SECURITY": "security",
    "PERFORMANCE": "quality",
}

# Vendored splinter SQL location (Plan 01 shipped it inside the wheel tree).
_SPLINTER_PACKAGE = "repo_audit.vendor.splinter"
_SPLINTER_RESOURCE = "splinter.sql"


def _dimension_for(categories: Any) -> Dimension:
    """Map splinter ``categories`` (a list) to a 7-dimension value.

    First recognised category wins; default "security" (the floor is a security
    lint, so an unknown category errs toward the security dimension).
    """
    if isinstance(categories, (list, tuple)):
        for cat in categories:
            mapped = _CATEGORY_TO_DIMENSION.get(str(cat).upper())
            if mapped is not None:
                return mapped
    elif isinstance(categories, str):
        mapped = _CATEGORY_TO_DIMENSION.get(categories.upper())
        if mapped is not None:
            return mapped
    return "security"


def _verify_phrased_recommendation(row: dict[str, Any]) -> str:
    """Build a verify-phrased recommendation from a splinter row.

    Deliberately does NOT echo the raw ``detail``/``description`` (which may
    carry enforced/secure/protected) into report prose. Uses the rule ``name``
    + remediation URL and a "verify enforcement" caveat so the message stays
    CRIT-4-clean regardless of the row's wording. The raw detail is preserved
    verbatim in ``parsed_value`` (exempt from the tripwire).
    """
    name = str(row.get("name", "")).strip() or "unknown_lint"
    remediation = str(row.get("remediation", "")).strip()
    base = (
        f"splinter '{name}' flagged this object on a fresh ephemeral DB; "
        "this reflects the repo's intended schema, not production state. "
        "Verify enforcement against the live database before acting."
    )
    if remediation:
        base = f"{base} See: {remediation}"
    return base


def map_splinter_rows(rows: list[dict[str, Any]]) -> list[Finding]:
    """Map splinter 10-column rows to static/candidate verify-phrased Findings.

    Deterministic, DB-free. For each row:
      * ``rule_id = row["name"]``
      * ``severity`` from :data:`_LEVEL_TO_SEVERITY` (ERROR→major cap)
      * ``dimension`` from :data:`_CATEGORY_TO_DIMENSION` (default security)
      * ``confidence="candidate"``, ``evidence_type="static"``
      * a verify-phrased ``recommendation`` (NEVER enforced/secure/protected)
      * ``evidence.parsed_value`` = the full raw row + ``faithful_severity``

    Calls :func:`assert_verify_phrasing` on the batch before returning — a
    HARD CRIT-4 post-pass (it raises on violation).

    Args:
        rows: splinter lint rows (dicts with the 10 documented keys).

    Returns:
        One :class:`Finding` per row.
    """
    findings: list[Finding] = []
    for row in rows:
        level = str(row.get("level", "")).upper()
        severity: Severity = _LEVEL_TO_SEVERITY.get(level, "info")
        faithful: Severity = _LEVEL_TO_FAITHFUL_SEVERITY.get(level, severity)
        dimension = _dimension_for(row.get("categories"))

        # Provenance: the entire raw row (exempt from the tripwire) plus the
        # faithful severity preserved under the SCH-04 cap.
        parsed_value: dict[str, Any] = dict(row)
        parsed_value["faithful_severity"] = faithful

        finding = Finding(
            dimension=dimension,
            severity=severity,
            evidence=Evidence(
                tool="splinter",
                parsed_value=parsed_value,
            ),
            evidence_type="static",
            confidence="candidate",
            recommendation=_verify_phrased_recommendation(row),
            source_tool="splinter",
            source_collector="supabase-rls-static",
            rule_id=str(row.get("name", "")),
        )
        findings.append(finding)

    # HARD CRIT-4 post-pass before returning (Plan 01 tripwire).
    assert_verify_phrasing(findings)
    return findings


def run_splinter(dsn: str, *, timeout_seconds: float = 120.0) -> list[dict[str, Any]]:
    """Execute the vendored ``splinter.sql`` against ``dsn`` and return rows.

    Thin psycopg3 wrapper so :func:`map_splinter_rows` stays DB-free and
    unit-testable on the fixture. Reads the vendored SQL via
    ``importlib.resources`` (wheel-packaged), runs it with a ``dict_row``
    factory, and returns ``fetchall()`` — the uniform 10-column rows.

    Args:
        dsn: a ``postgresql://…`` connection string for the (ephemeral) DB.
        timeout_seconds: statement/connect timeout applied to the session.

    Returns:
        The raw splinter rows as a list of dicts.
    """
    import psycopg
    import psycopg.rows

    sql = (
        importlib.resources.files(_SPLINTER_PACKAGE) / _SPLINTER_RESOURCE
    ).read_text(encoding="utf-8")

    # splinter.sql is a `set local search_path = '';` prefix followed by ONE
    # big `( with … select … )` result query. psycopg3 returns only the LAST
    # statement's result set from a multi-statement execute, and that final
    # state can land on the SET ("the last operation didn't produce records;
    # command status: SET"). Split the leading SET off and run the SELECT alone
    # so fetchall() always targets the lint query. The SET is applied at session
    # scope first (search_path = '' so unqualified names never resolve, matching
    # splinter's intent).
    setup_stmts, query = _split_splinter_sql(sql)

    # connect_timeout bounds the handshake; statement_timeout (ms) bounds the
    # lint query itself so a pathological catalog never hangs the scan.
    connect_kwargs: dict[str, Any] = {
        "connect_timeout": int(max(1, timeout_seconds)),
    }
    with psycopg.connect(dsn, **connect_kwargs) as conn:
        with conn.cursor() as setup_cur:
            setup_cur.execute(
                f"SET statement_timeout = {int(max(1, timeout_seconds) * 1000)}"
            )
            # search_path = '' (and any other leading session SET splinter ships).
            setup_cur.execute("SET search_path = ''")
            for stmt in setup_stmts:
                setup_cur.execute(stmt)
        with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(query)
            return list(cur.fetchall())


def _split_splinter_sql(sql: str) -> tuple[list[str], str]:
    """Split splinter.sql into leading session SETs + the final result query.

    Strips SQL comment lines, then peels any leading ``SET …;`` statements off
    the front (run at session scope) so the remaining ``( with … select … )``
    is executed alone and ``fetchall()`` targets it. Returns
    ``(setup_statements, query)``. Robust to the SET being absent.
    """
    # Drop full-line comments so they don't confuse the SET-prefix detection.
    body_lines = [
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    ]
    body = "\n".join(body_lines).strip()

    setup: list[str] = []
    # Peel leading `set …;` statements (case-insensitive) off the front.
    remaining = body
    while True:
        stripped = remaining.lstrip()
        if stripped[:4].lower() != "set ":
            break
        semi = stripped.find(";")
        if semi == -1:
            break
        setup.append(stripped[: semi + 1])
        remaining = stripped[semi + 1 :]

    query = remaining.strip()
    return setup, query


__all__ = [
    "map_splinter_rows",
    "run_splinter",
]
