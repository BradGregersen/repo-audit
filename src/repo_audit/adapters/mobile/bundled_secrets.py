"""MOB-02 (9-T2) — Tier-2 Expo/RN config + JS bundled-secret pass.

The half mobsfscan structurally cannot do: mobsfscan does NOT scan JS/TS source
(verified live in 09-RESEARCH), so an Expo app whose secrets live in
``app.config.js`` / ``eas.json`` / ``.ts`` source slips straight past Tier 1.
This module is the dedicated Expo/RN config-file + JS surface pass.

Reuse discipline (mandatory — one source of truth keeps MOB-02 / SAST / RLS-04
consistent): the service_role marker table, the anon allowlist, and the
``[REDACTED:N]`` value-blind redaction are IMPORTED verbatim from
``adapters/supabase/footguns.py`` — they are NOT re-declared here. The only new
engineering is (a) the Expo config-file glob set and (b) a JWT ``role``-claim
decoder that discriminates the public ``anon`` key (allowlist) from a shipped
``service_role`` key (flag).

Why this matters: a shipped ``service_role`` key reaches every user and BYPASSES
RLS entirely — the catastrophic high-density ``adapt`` win. The public anon /
``sb_publishable_*`` key belongs in the client and must NEVER be flagged, even
behind an ``EXPO_PUBLIC_`` prefix (Expo inlines ``EXPO_PUBLIC_*`` into the JS
bundle at build time — that prefix is PUBLIC by design; 09-RESEARCH A1).

Evidence discipline (mirrors footguns):
  * Every finding is ``evidence_type="heuristic"``, ``confidence="candidate"``,
    ``severity="major"`` (SCH-04 candidate cap forbids critical/blocker),
    ``dimension="security"``, verify-phrased (passes the shared CRIT-4
    :func:`assert_verify_phrasing` tripwire — no enforced/secure/protected).
  * Every matched span is REDACTED to ``[REDACTED:N]`` at the collector boundary
    (T-09-04 / SCH-08 defense-in-depth) — the raw token bytes NEVER enter a
    Finding.

Never raises across its boundary: any internal error yields
``AdapterResult(status="unavailable")``; a clean repo yields
``AdapterResult(status="ok", findings=[])``.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.supabase.footguns import (
    _ANON_ALLOWLIST,
    _SERVICE_ROLE_MARKERS,
    _has_non_anon_marker,
    _redact_span,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.schema.finding import Evidence, Finding

__all__ = ["scan_bundled_secrets", "_jwt_role"]

_SOURCE_ADAPTER = "mobile"
_SOURCE_TOOL = "bundled-secrets"
_DIMENSION = "security"
_RULE_ID = "bundled_service_role_secret"

# --- Config-file surface (the Expo glob set from 09-RESEARCH Pattern 2) -------
# Matched at the repo root. ``.env.*`` is handled via a prefix check below.
_CONFIG_FILES: tuple[str, ...] = (
    "app.config.js",
    "app.config.ts",
    "app.json",
    "eas.json",
    "google-services.json",
    ".env",
)
# Native Android string resources at their canonical path (relative to repo).
_NATIVE_CONFIG_RELPATHS: tuple[tuple[str, ...], ...] = (
    ("android", "app", "src", "main", "res", "values", "strings.xml"),
)
# JS/TS source roots walked for inline secrets.
_SOURCE_DIRS: tuple[str, ...] = ("app", "src", "components")
_SOURCE_SUFFIXES: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
)

# Build/test dirs to skip — mirrors footguns' _EXCLUDE_PARTS discipline so the
# two passes agree on what is out-of-scope. (Replicated locally rather than
# imported because footguns scopes to CLIENT dirs only and excludes server/api,
# which we deliberately DO want to scan for a shipped service_role; see source
# note: repo_audit.adapters.supabase.footguns._EXCLUDE_PARTS.)
_EXCLUDE_PARTS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".expo",
        ".next",
        "dist",
        "build",
        "coverage",
        "__tests__",
        "__mocks__",
    }
)
_TEST_FILE_INFIXES: tuple[str, ...] = (".test.", ".spec.")

# JWT-shaped token: header.payload.signature, Supabase tokens start `eyJ`.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _jwt_role(token: str) -> str | None:
    """Decode the UNVERIFIED ``role`` claim from a JWT payload (stdlib only).

    Recipe (09-RESEARCH Pattern 2): split on ``.``, take the payload segment,
    pad to a multiple of 4, ``base64.urlsafe_b64decode``, ``json.loads``, return
    the ``role`` claim. We never verify the signature — the role claim alone
    discriminates the public ``anon`` key (allowlist) from a shipped
    ``service_role`` key (flag). NO crypto-JWT library.

    Args:
        token: a candidate JWT string.

    Returns:
        the ``role`` claim string, or ``None`` if the token is not a decodable
        JWT (in which case the caller falls back to marker/prefix rules).
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # pad to a multiple of 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        role = payload.get("role")
        return role if isinstance(role, str) else None
    except Exception:  # noqa: BLE001 — not a JWT / undecodable -> fall through
        return None


def _is_excluded(rel_parts: tuple[str, ...], filename: str) -> bool:
    """Return True when a path is in a build/test dir out of scope.

    Mirrors ``footguns._is_excluded`` (build output + test/mock dirs + ``*.test.*``
    / ``*.spec.*``), minus footguns' client-only server/api/functions exclusion —
    a shipped service_role anywhere in the repo's config+source is in scope here.
    """
    if any(part in _EXCLUDE_PARTS for part in rel_parts):
        return True
    if any(infix in filename for infix in _TEST_FILE_INFIXES):
        return True
    return False


def _iter_target_files(repo: Path):
    """Yield ``(path, rel)`` for every config + JS/TS file in the scan surface."""
    seen: set[Path] = set()

    # Root config files (incl. .env.* variants).
    for child in repo.iterdir() if repo.is_dir() else ():
        if not child.is_file():
            continue
        name = child.name
        if name in _CONFIG_FILES or name.startswith(".env."):
            seen.add(child)
            yield child, child.relative_to(repo)

    # Native config files at their canonical relative paths.
    for parts in _NATIVE_CONFIG_RELPATHS:
        path = repo.joinpath(*parts)
        if path.is_file() and path not in seen:
            seen.add(path)
            yield path, path.relative_to(repo)

    # JS/TS source under the source roots.
    for root_name in _SOURCE_DIRS:
        root = repo / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path in seen:
                continue
            if path.suffix not in _SOURCE_SUFFIXES:
                continue
            rel = path.relative_to(repo)
            if _is_excluded(rel.parts, path.name):
                continue
            seen.add(path)
            yield path, rel


def _build_finding(rel: Path, lineno: int, raw_line: str, classifier: str) -> Finding:
    """Construct the heuristic/candidate verify-phrased bundled-secret finding.

    ``classifier`` records WHY the line flagged (``jwt_role:service_role`` or a
    ``marker:<pattern>`` tag) for triage — it never carries the raw value. The
    span is redacted via the imported ``footguns._redact_span`` (T-09-04).
    """
    redacted = _redact_span(raw_line)
    recommendation = (
        "A service_role-style secret appears bundled into the Expo/RN config or "
        "JS surface; verify it is NOT shipped to clients (the service_role key "
        "bypasses RLS — a shipped copy hands every user god-mode). The public "
        "anon / sb_publishable_ key is allowlisted and never flagged. Cross-check "
        "the MOB-01 mobsfscan pass, the SAST secrets rules, and the RLS analysis."
    )
    caveat = (
        "Heuristic bundled-secret match (service_role marker or decoded "
        "role=='service_role' JWT claim), not a value-confirmed live key; "
        "corroborate with MOB-01 / SAST / RLS before acting."
    )
    snippet = f"{rel}:{lineno} — bundled secret {redacted}"
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
                "redacted_len": min(len(raw_line.strip()), 80),
                "cross_link": ["MOB-01", "SAST", "RLS"],
                "classifier": classifier,
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


def _classify_line(line: str) -> str | None:
    """Decide whether a line carries a shipped service_role secret.

    Detection order (09-RESEARCH Pattern 2):
      1. Any JWT-shaped token: decode the role claim. role=='service_role' ->
         FLAG; role=='anon' -> ALLOWLIST (skip the whole line, even behind an
         EXPO_PUBLIC_ name); None -> fall through to marker rules.
      2. Anon allowlist match with NO service_role-distinct marker -> skip.
      3. Any service_role marker (sb_secret_, SERVICE_ROLE, ...) -> FLAG.
      4. The EXPO_PUBLIC_ A1 rule is subsumed: an EXPO_PUBLIC_* line flags ONLY
         when the same line also matches a service_role marker (step 3) or
         decodes to role=='service_role' (step 1) — a bare
         EXPO_PUBLIC_SUPABASE_ANON_KEY decodes to role=='anon' / matches the
         allowlist and is never flagged.

    Returns a classifier tag when the line should FLAG, else ``None``.
    """
    for token in _JWT_RE.findall(line):
        role = _jwt_role(token)
        if role == "service_role":
            return "jwt_role:service_role"
        if role == "anon":
            # The public anon key — allowlisted, never flagged for this line.
            return None

    matched_anon = any(p.search(line) for p in _ANON_ALLOWLIST)
    if matched_anon and not _has_non_anon_marker(line):
        # Benign public key reference with no service_role-distinct marker.
        return None

    for pattern in _SERVICE_ROLE_MARKERS:
        if pattern.search(line):
            return f"marker:{pattern.pattern}"

    return None


def scan_bundled_secrets(repo: Path) -> AdapterResult:
    """Scan the Expo/RN config + JS surface for shipped service_role secrets.

    Walks the Expo config-file set (``app.config.{js,ts}``, ``app.json``,
    ``eas.json``, ``google-services.json``, ``.env`` / ``.env.*``), the native
    ``android/.../strings.xml``, and JS/TS source under ``app/`` / ``src/`` /
    ``components/`` (skipping build/test dirs). For each line, classifies via
    :func:`_classify_line`: a decoded ``role=='service_role'`` JWT or a
    ``_SERVICE_ROLE_MARKERS`` match FLAGS; the public anon / ``sb_publishable_``
    key (allowlist or decoded ``role=='anon'``) is NEVER flagged, even behind an
    ``EXPO_PUBLIC_`` prefix. Every flagged span is redacted to ``[REDACTED:N]``.

    Never raises: any internal error -> ``AdapterResult(status="unavailable")``.
    A clean repo (no service_role) -> ``AdapterResult(status="ok", findings=[])``.

    Args:
        repo: the target repository root.

    Returns:
        ``AdapterResult`` with heuristic findings (status ``"ok"``), or
        ``status="unavailable"`` on any internal error. No registration here —
        Plan 05 wires this into the scan runner.
    """
    try:
        findings: list[Finding] = []
        for path, rel in _iter_target_files(repo):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                classifier = _classify_line(line)
                if classifier is not None:
                    findings.append(
                        _build_finding(rel, lineno, line, classifier)
                    )

        # HARD CRIT-4 post-pass: heuristic findings must be verify-phrased.
        assert_verify_phrasing(findings)
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return AdapterResult(
            status="unavailable",
            findings=[],
            notes=(
                f"bundled-secret pass degraded: "
                f"{type(exc).__name__}: {str(exc)[:160]}"
            ),
            source_adapter=_SOURCE_ADAPTER,
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
        )

    return AdapterResult(
        status="ok",
        findings=findings,
        notes=(
            f"Expo/RN bundled-secret pass: {len(findings)} candidate "
            "service_role secret(s) (config+JS surface; anon key allowlisted)"
        ),
        source_adapter=_SOURCE_ADAPTER,
        source_tool=_SOURCE_TOOL,
        dimension=_DIMENSION,
    )
