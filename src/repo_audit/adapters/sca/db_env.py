"""Persistent vuln-DB cache env (FND-03) — escapes the tempdir XDG redirect.

RESEARCH Open-Q2 RESOLVED here. ``build_scan_env`` (cache_env.py) redirects
``XDG_CACHE_HOME`` to a throwaway PER-SCAN tempdir for read-only hygiene — but
the pinned vuln DB must PERSIST across scans (it is the reproducibility snapshot
the whole phase rests on). So the two DB-cache dirs must intentionally ESCAPE
that redirect.

:func:`sca_db_dir` resolves a STABLE path from the REAL process environment
(``os.environ['XDG_CACHE_HOME']`` or ``~/.cache``) — NOT from the tempdir-redirected
dict ``build_scan_env`` returns. :func:`build_sca_env` then layers the four
osv/grype DB-cache env keys ON TOP of whatever base env it is handed, overriding
them to the persistent path:

    * ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`` → ``<persistent>/osv``
    * ``GRYPE_DB_CACHE_DIR``                   → ``<persistent>/grype``
    * ``GRYPE_DB_AUTO_UPDATE=false``           (pinned: no network auto-update)
    * ``GRYPE_DB_VALIDATE_AGE=false``          (a pinned DB is intentionally aged)

Every OTHER tool's cache stays redirected to the tempdir; only these two DB
dirs escape it (the snapshot lives outside the per-scan tempdir AND outside the
target repo — SC-6 read-only contract, T-07-13).

:func:`parse_grype_db_status` reads the ``Built:`` timestamp out of
``grype db status`` text for FeedProvenance ``db_snapshot_date`` (advisory_count
is None — ``grype db status`` reports no record count, PROVENANCE.md A3; the
deterministic-numbers rule forbids inventing one).
"""
from __future__ import annotations

import os
import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional

# grype db status "Built:" line, e.g. "Built:     2026-06-01T08:11:23Z".
_BUILT_RE = re.compile(r"^\s*Built:\s*(?P<ts>\S+)", re.MULTILINE)


def sca_db_dir() -> Path:
    """Return the STABLE persistent vuln-DB base dir (created), outside any repo.

    Reads ``XDG_CACHE_HOME`` directly from :data:`os.environ` (falling back to
    ``~/.cache``) so the path is computed from the REAL user environment — it does
    NOT pick up the per-scan tempdir XDG redirect that ``build_scan_env`` injects
    into its OWN returned dict (RESEARCH Open-Q2: the DB dirs intentionally escape
    the redirect so the pinned snapshot persists across scans).

    Returns:
        ``<XDG_CACHE_HOME or ~/.cache>/repo-audit/vuln-db`` (mkdir'd).
    """
    cache_home = os.environ.get("XDG_CACHE_HOME")
    base = Path(cache_home) if cache_home else (Path.home() / ".cache")
    db_dir = base / "repo-audit" / "vuln-db"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir


def build_sca_env(base_env: dict[str, str]) -> dict[str, str]:
    """Layer the four persistent osv/grype DB-cache keys on top of ``base_env``.

    Args:
        base_env: the base child env — typically a ``build_scan_env`` result with
            ``XDG_CACHE_HOME`` already redirected to a per-scan tempdir. This
            function does NOT mutate it.

    Returns:
        A NEW dict: a copy of ``base_env`` with
        ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`` / ``GRYPE_DB_CACHE_DIR`` pointed
        at the PERSISTENT :func:`sca_db_dir` subdirs (escaping any tempdir
        redirect in ``base_env``) plus ``GRYPE_DB_AUTO_UPDATE=false`` and
        ``GRYPE_DB_VALIDATE_AGE=false`` (the pinned-mode no-network posture).
    """
    db_dir = sca_db_dir()
    osv_dir = db_dir / "osv"
    grype_dir = db_dir / "grype"
    osv_dir.mkdir(parents=True, exist_ok=True)
    grype_dir.mkdir(parents=True, exist_ok=True)

    env = dict(base_env)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(osv_dir)
    env["GRYPE_DB_CACHE_DIR"] = str(grype_dir)
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    env["GRYPE_DB_VALIDATE_AGE"] = "false"
    return env


def parse_grype_db_status(text: str) -> tuple[Optional[date], Optional[int]]:
    """Parse ``grype db status`` text → ``(db_snapshot_date, advisory_count)``.

    The ``Built:`` line carries an ISO-8601 timestamp (e.g.
    ``2026-06-01T08:11:23Z``); we return its DATE. ``grype db status`` does NOT
    report a vulnerability RECORD COUNT (PROVENANCE.md A3), so ``advisory_count``
    is ALWAYS ``None`` here — the deterministic-numbers rule forbids inventing a
    count we cannot cleanly read.

    Returns:
        ``(date, None)`` when a parseable ``Built:`` timestamp is present;
        ``(None, None)`` when it is absent or unparseable.
    """
    match = _BUILT_RE.search(text or "")
    if not match:
        return (None, None)
    raw = match.group("ts").strip()
    parsed = _parse_iso_date(raw)
    return (parsed, None)


def _parse_iso_date(raw: str) -> Optional[date]:
    """Best-effort ISO-8601 → date; never raises (returns None on a bad value)."""
    candidate = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate).date()
    except ValueError:
        # Fall back to a bare date prefix (YYYY-MM-DD) when the time part is odd.
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None


__all__ = ["build_sca_env", "parse_grype_db_status", "sca_db_dir"]
