"""RLS-04 service_role-in-client footgun grep (Plan 08-04, Task 1).

The one RLS-04 footgun splinter cannot catch: a Supabase ``service_role`` key
(which BYPASSES RLS entirely) reachable from CLIENT code, where it would ship in
the bundle and hand any user god-mode over every tenant's data. splinter lints
the database; this is a deliberately-tiny STATIC grep of the repo's source
(D-08-11 — a grep, NOT an AST/dataflow pass) that complements the native lints.

Scope discipline (D-08-12):
  * CLIENT PATHS ONLY. We walk ``app/``, ``src/``, ``components/`` and skip
    ``supabase/functions/`` (edge runtime — service_role is legitimate there),
    server-only dirs (``server/``, ``api/``), ``__tests__/`` + ``*.test.*`` /
    ``*.spec.*`` (service_role in test fixtures is expected), plus the usual
    build/output dirs. A hit OUTSIDE client-reachable code is NOT our concern.
  * ANON-KEY ALLOWLIST. The PUBLIC ``EXPO_PUBLIC_SUPABASE_ANON_KEY`` /
    ``sb_publishable_*`` / a bare publishable anon JWT is SUPPOSED to be in the
    client and is NEVER flagged (the project-wide SAST-03/MOB-02 rule).
  * CROSS-LINK, DON'T DUPLICATE. Findings carry a note pointing at the MOB-02
    bundled-secrets / SAST passes rather than re-doing their high-entropy value
    detection — this is a reference-SHAPE (env-name / call-shape) grep.

Evidence discipline:
  * Every finding is ``evidence_type="heuristic"``, ``confidence="candidate"``,
    ``severity="major"`` (the SCH-04 candidate cap forbids critical/blocker),
    ``dimension="security"``, verify-phrased (it passes the shared CRIT-4
    :func:`assert_verify_phrasing` tripwire — no enforced/secure/protected).
  * The matched span is REDACTED to ``[REDACTED:N]`` (T-08-16) — the raw key
    value NEVER enters the Finding (SCH-08 is also structurally enforced by the
    schema, this is defense-in-depth at the collector boundary).

Decision (D-08 discretion): this module stands alone with its own marker table
rather than coupling to ``collectors/secret_detection``'s entropy/known-pattern
engine. The markers here are reference-SHAPE (an env-var NAME, an ``sb_secret_``
prefix, a ``createClient(url, serviceRoleKey)`` call shape) — not high-entropy
VALUE detection — so the engines answer different questions; coupling would
muddy both. Never raises across its boundary (returns ``unavailable`` on error).
"""
from __future__ import annotations

import re
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.schema.finding import Evidence, Finding

# --- Marker table (reference-shape, NOT high-entropy value detection) -------
# Each pattern matches a service_role-style REFERENCE reachable from a client.
# The banned words for verify-phrasing live in verify_phrasing._BANNED, not
# here — these are detection markers, scanned over target source, never our
# own report prose.
_SERVICE_ROLE_MARKERS: tuple[re.Pattern[str], ...] = (
    # The canonical env-var name for the RLS-bypassing key.
    re.compile(r"SUPABASE_SERVICE_ROLE_KEY"),
    # A bare SERVICE_ROLE env reference (e.g. process.env.SERVICE_ROLE).
    re.compile(r"\bSERVICE_ROLE\b"),
    # The modern secret-key prefix (sb_secret_...). Value bytes are NOT used.
    re.compile(r"sb_secret_"),
    # createClient(<url>, <serviceRole-named identifier>) — the second
    # positional arg bound to a service-role-named identifier (heuristic).
    re.compile(r"createClient\s*\([^,]*,\s*[A-Za-z0-9_]*[Ss]ervice[_]?[Rr]ole"),
)

# --- Anon-key allowlist (NEVER flagged — the public key belongs in the client)
_ANON_ALLOWLIST: tuple[re.Pattern[str], ...] = (
    re.compile(r"EXPO_PUBLIC_SUPABASE_ANON_KEY"),
    re.compile(r"SUPABASE_ANON_KEY"),
    re.compile(r"sb_publishable_"),
    re.compile(r"\bANON_KEY\b"),
    re.compile(r"\banonKey\b"),
)

# --- Path scoping -----------------------------------------------------------
# Client-reachable roots we walk. A repo without these simply yields no hits.
_CLIENT_DIRS: tuple[str, ...] = ("app", "src", "components")

# Path PARTS that exclude a file from the client-reachable grep. Resolved at
# call time against the file's path-parts relative to the repo.
_EXCLUDE_PARTS: frozenset[str] = frozenset(
    {
        "functions",  # supabase/functions edge runtime (guarded with 'supabase')
        "server",
        "api",
        "__tests__",
        "__mocks__",
        "node_modules",
        ".expo",
        ".next",
        "dist",
        "build",
        "coverage",
    }
)

# Filename infixes that mark a test/spec file (service_role legitimate there).
_TEST_FILE_INFIXES: tuple[str, ...] = (".test.", ".spec.")

# Source extensions we read (client TS/JS surface).
_SOURCE_SUFFIXES: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
)

_RULE_ID = "service_role_reachable_from_client"
_SOURCE_TOOL = "supabase-footguns"
_DIMENSION = "security"

# Bound the redacted-span echo so a long line never floods the report.
_SPAN_CAP = 80


def _is_excluded(rel_parts: tuple[str, ...], filename: str) -> bool:
    """Return True when a relative path is OUTSIDE client-reachable scope.

    Excludes ``supabase/functions/`` (edge), server-only dirs, test/mock dirs
    and build output, plus ``*.test.*`` / ``*.spec.*`` filenames.
    """
    # supabase/functions/ — the edge runtime; service_role is legitimate there.
    for i in range(len(rel_parts) - 1):
        if rel_parts[i] == "supabase" and rel_parts[i + 1] == "functions":
            return True
    if any(part in _EXCLUDE_PARTS for part in rel_parts):
        return True
    if any(infix in filename for infix in _TEST_FILE_INFIXES):
        return True
    return False


def _iter_client_files(repo: Path):
    """Yield client-reachable source files under ``_CLIENT_DIRS`` in scope."""
    for root_name in _CLIENT_DIRS:
        root = repo / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in _SOURCE_SUFFIXES:
                continue
            rel = path.relative_to(repo)
            if _is_excluded(rel.parts, path.name):
                continue
            yield path, rel


def _redact_span(line: str) -> str:
    """Return a value-blind redaction of a matched line (never the raw value).

    We echo the LENGTH only — ``[REDACTED:N]`` — so a report can show that
    *something* matched at this line without surfacing the literal key bytes
    (T-08-16 / SCH-08 defense-in-depth).
    """
    stripped = line.strip()
    n = min(len(stripped), _SPAN_CAP)
    return f"[REDACTED:{n}]"


def _build_finding(rel: Path, lineno: int, raw_line: str) -> Finding:
    """Construct the heuristic/candidate verify-phrased footgun finding."""
    redacted = _redact_span(raw_line)
    # Verify-phrased: "present; verify ..." — NO enforced/secure/protected.
    recommendation = (
        "A service_role-style key reference is present in client-reachable "
        "code; verify it is NOT shipped in the client bundle (the service_role "
        "key bypasses RLS). Cross-check the MOB-02 bundled-secrets analysis and "
        "the SAST secrets pass — this grep flags the reference shape only, it "
        "does not confirm the key value is real."
    )
    caveat = (
        "Heuristic reference-shape match (env-name / call-shape), not a "
        "value-confirmed secret; corroborate with MOB-02 / SAST before acting."
    )
    snippet = f"{rel}:{lineno} — service_role reference {redacted}"
    return Finding(
        dimension=_DIMENSION,
        severity="major",  # SCH-04 candidate cap forbids critical/blocker
        file=str(rel),
        line=lineno,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=snippet,
            parsed_value={
                "rule_id": _RULE_ID,
                "cross_link": ["MOB-02", "SAST"],
                "redacted_len": min(len(raw_line.strip()), _SPAN_CAP),
            },
        ),
        evidence_type="heuristic",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id=_RULE_ID,
        confidence_caveat=caveat,
    )


def scan_service_role_in_client(repo: Path) -> AdapterResult:
    """Grep client-reachable source for a service_role-style key reference.

    Walks ``app/``, ``src/``, ``components/`` (client-reachable roots), skipping
    ``supabase/functions/`` (edge), server-only dirs, ``__tests__/`` +
    ``*.test.*`` / ``*.spec.*`` and build output. For each line matching a
    ``_SERVICE_ROLE_MARKERS`` pattern that does NOT also match the
    ``_ANON_ALLOWLIST``, emits one heuristic/candidate verify-phrased Finding
    with a REDACTED span and a MOB-02/SAST cross-link.

    Never raises across its boundary: any error yields
    ``AdapterResult(status="unavailable")``. A clean repo (no client code or no
    hits) yields ``AdapterResult(status="ok", findings=[])`` — a clean result,
    NOT unavailable.

    Args:
        repo: the target repository root.

    Returns:
        ``AdapterResult`` with heuristic findings (status ``"ok"``), or
        ``status="unavailable"`` on any internal error.
    """
    try:
        findings: list[Finding] = []
        for path, rel in _iter_client_files(repo):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(p.search(line) for p in _ANON_ALLOWLIST):
                    # The line references the PUBLIC anon/publishable key —
                    # allowlisted, never flagged (even if a marker also matches).
                    if not _has_non_anon_marker(line):
                        continue
                if any(p.search(line) for p in _SERVICE_ROLE_MARKERS):
                    findings.append(_build_finding(rel, lineno, line))

        # HARD CRIT-4 post-pass: heuristic findings must be verify-phrased.
        assert_verify_phrasing(findings)
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=f"footgun grep degraded: {type(exc).__name__}: {str(exc)[:160]}",
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
        )

    return AdapterResult(
        status="ok",
        findings=findings,
        notes=(
            f"service_role-in-client grep: {len(findings)} candidate "
            "reference(s) (client paths only; anon key allowlisted)"
        ),
        source_tool=_SOURCE_TOOL,
        dimension=_DIMENSION,
    )


def _has_non_anon_marker(line: str) -> bool:
    """True when a line carries a service_role marker NOT covered by the anon
    allowlist — i.e. a line that mixes the public anon key and a genuine
    service_role reference still gets flagged for the service_role half.

    A line matching ONLY the anon allowlist (no service_role-distinct marker)
    is benign. The ``SERVICE_ROLE`` / ``SUPABASE_SERVICE_ROLE_KEY`` /
    ``sb_secret_`` / service-role-arg markers are all anon-distinct.
    """
    return any(p.search(line) for p in _SERVICE_ROLE_MARKERS)


__all__ = ["scan_service_role_in_client"]
