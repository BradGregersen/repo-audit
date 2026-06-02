"""FeedProvenance builder (FND-02 / D-07-02) — one stamped entry per scanner.

``build_feed_provenance`` turns the osv + grype collection results into the
per-source reproducibility stamp ``ReportMeta.feed_provenance`` carries (Plan 01
defined the model). Exactly ONE :class:`FeedProvenance` entry per AVAILABLE
scanner:

    * osv entry — ALWAYS (osv is the floor; collect_osv either ran ok or the
      whole SCA dimension is unavailable and run_sca short-circuits before this).
    * grype entry — ONLY when ``grype_result.status == "ok"`` (grype is optional,
      D-07-10); an absent/timed-out grype contributes NO entry.

Honesty rules (deterministic collectors own all numbers):

    * ``db_snapshot_date`` — osv: the mtime DATE of the downloaded DB file under
      ``sca_db_dir()/"osv"`` (A2 — osv emits no build date), or None when no DB
      file is present; grype: parsed from ``grype_result.db_snapshot_date`` (the
      ``descriptor.db.status.built`` timestamp collect_grype already extracted),
      or None.
    * ``advisory_count`` — None for BOTH scanners (neither reports a clean total;
      PROVENANCE.md A3). Ship None over an invented number.
    * ``queried_at`` — the caller's scan wall-clock; lives ONLY here, never on a
      Finding (Pitfall 7 / SC-5 bit-identity).
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Optional

from repo_audit.adapters.sca.db_env import sca_db_dir
from repo_audit.adapters.sca.grype import GrypeResult
from repo_audit.adapters.sca.osv import OsvResult
from repo_audit.schema.report import FeedProvenance

_OSV_FEED = "OSV"
_OSV_SCANNER = "osv-scanner"
_GRYPE_FEED = "GitHub Advisory / NVD (Grype DB)"
_GRYPE_SCANNER = "grype"


def _osv_db_snapshot_date() -> Optional[date]:
    """DATE of the newest osv DB file under the persistent cache (A2), or None.

    osv-scanner emits no DB build date in its output, so the snapshot date is the
    mtime of the downloaded DB file under ``sca_db_dir()/"osv"``. When the dir is
    empty (DB not yet seeded) we return None rather than inventing a date.
    """
    osv_dir = sca_db_dir() / "osv"
    if not osv_dir.is_dir():
        return None
    newest_mtime: Optional[float] = None
    for path in osv_dir.rglob("*"):
        try:
            if path.is_file():
                mtime = path.stat().st_mtime
                if newest_mtime is None or mtime > newest_mtime:
                    newest_mtime = mtime
        except OSError:
            continue
    if newest_mtime is None:
        return None
    return datetime.fromtimestamp(newest_mtime).date()


def _grype_db_snapshot_date(grype_result: GrypeResult) -> Optional[date]:
    """Parse the grype ``built`` timestamp string → DATE, or None."""
    raw = grype_result.db_snapshot_date
    if not isinstance(raw, str) or not raw:
        return None
    candidate = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate).date()
    except ValueError:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None


def build_feed_provenance(
    osv_result: OsvResult,
    grype_result: GrypeResult,
    *,
    queried_at: datetime,
) -> list[FeedProvenance]:
    """Build the per-source FeedProvenance list (one entry per available scanner).

    Args:
        osv_result: the :class:`OsvResult` from ``collect_osv``.
        grype_result: the :class:`GrypeResult` from ``collect_grype``.
        queried_at: the scan wall-clock timestamp (header-only metadata).

    Returns:
        ``[osv_entry]`` when grype is unavailable; ``[osv_entry, grype_entry]``
        when grype ran ok. advisory_count is None on every entry (no clean count
        is reported by either tool — never invented).
    """
    entries: list[FeedProvenance] = [
        FeedProvenance(
            feed=_OSV_FEED,
            scanner=_OSV_SCANNER,
            scanner_version=osv_result.scanner_version or "unknown",
            db_snapshot_date=_osv_db_snapshot_date(),
            queried_at=queried_at,
            advisory_count=None,
        )
    ]

    if grype_result.status == "ok":
        entries.append(
            FeedProvenance(
                feed=_GRYPE_FEED,
                scanner=_GRYPE_SCANNER,
                scanner_version=grype_result.scanner_version or "unknown",
                db_snapshot_date=_grype_db_snapshot_date(grype_result),
                queried_at=queried_at,
                advisory_count=None,
            )
        )

    return entries


__all__ = ["build_feed_provenance"]
