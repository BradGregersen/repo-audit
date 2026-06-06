"""Today-inclusive sidecar loader for ``repo-audit issues`` (Phase 19, Plan 19-02).

This resolves CONTEXT decision D-01 and RESEARCH Open Question 1: the issue
filer must draft from the MOST-RECENT sidecar INCLUDING today's, because the
auditor runs ``repo-audit scan`` and then immediately ``repo-audit issues`` on the report
just written. That is the exact opposite of the trend baseline selector in
``meta/paths.find_prior_sidecar``, which deliberately excludes today (so a
same-day re-run compares against the previous day, not the report it just
emitted). Reusing ``find_prior_sidecar`` here would be the anti-pattern named
in 19-RESEARCH Pitfall 1 — it would silently skip today's sidecar and draft
from a stale baseline (or nothing at all).

So ``find_latest_sidecar`` copies that loop VERBATIM with one surgical change:
the future-date exclusion guard is dropped (the one comparing each sidecar's
date against the current day). Selection still
keys on the AUTHORITATIVE ``meta.scan_date`` inside each payload, NOT the
filename (filenames carry -2/-3 collision suffixes and are hand-editable).

Security (T-19-03, Tampering / DoS): a target repo's
``docs/state-reports/*.json`` is hand-editable untrusted input (Security V5).
Each file is parsed via ``ScanReport.model_validate_json`` (extra='forbid');
any ``ValidationError`` / ``json.JSONDecodeError`` / ``OSError`` / ``ValueError``
skips that file rather than crashing. ``load_scan_report`` NEVER raises on a
hostile payload — it returns ``None``. ``load_latest_sidecar`` raises only the
domain-level ``NoSidecarError`` (a clear, actionable message — not a stack
trace) when no usable sidecar exists at all.
"""
from __future__ import annotations

import json
import warnings
from datetime import date
from pathlib import Path

from pydantic import ValidationError

# Sidecars older than this WARN (D-01 staleness disclosure) but still load —
# the filer proceeds against a stale report rather than refusing, because a
# stale finding set is still actionable; the warning is the honest disclosure.
STALE_AFTER_DAYS: int = 30


class NoSidecarError(Exception):
    """Raised when no usable ScanReport sidecar exists for a repo.

    Carries a clear, actionable message (run ``repo-audit scan`` first) — NOT a raw
    stack trace. The CLI surfaces this as a one-line error.
    """


def find_latest_sidecar(repo_path: Path) -> Path | None:
    """Return the most-recent JSON sidecar by ``meta.scan_date`` — today INCLUDED.

    This is the D-01 / OQ1 resolution: unlike ``meta.paths.find_prior_sidecar``
    (which excludes today), this selects today's sidecar when present, because
    ``repo-audit issues`` drafts from the report ``repo-audit scan`` just wrote.

    Reads the AUTHORITATIVE ``meta.scan_date`` from inside each sidecar (NOT the
    filename, which carries collision suffixes and is hand-editable).

    Security (T-19-03): each file is parsed via ``ScanReport.model_validate_json``
    (extra='forbid'); a corrupt / hostile / unreadable sidecar is skipped, not
    crashed.

    Returns:
        The Path of the JSON sidecar with the maximum ``meta.scan_date``
        (today-inclusive), or ``None`` when no usable sidecar exists (no dir,
        no JSON, all unparseable).
    """
    # Deferred import: report.py pulls in the agent schema chain; keep this
    # module cheap to import for callers that never touch sidecars.
    from repo_audit.schema.report import ScanReport

    out_dir = Path(repo_path) / "docs" / "state-reports"
    if not out_dir.is_dir():
        return None

    # WR-02: iterate in a deterministic mtime order (oldest → newest) and break a
    # same-day scan_date tie toward the LATER-WRITTEN file. ``Path.glob`` order is
    # filesystem-dependent and unsorted, so on the expected same-day-collision
    # case (running ``repo-audit scan`` twice in one day, the exact scenario this loader
    # exists for) an unordered glob could silently draft from the OLDER same-day
    # sidecar. Sorting by mtime first, then using ``>=`` on the date tie, makes
    # the newest-written same-day sidecar deterministically win.
    candidates = sorted(out_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)

    best_path: Path | None = None
    best_date: date | None = None
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8")
            report = ScanReport.model_validate_json(text)
        except (ValidationError, json.JSONDecodeError, OSError, ValueError):
            # Corrupt / hostile / unreadable sidecar → skip; a valid sibling is
            # still returned. Does NOT crash (T-19-03 mitigation).
            continue
        sidecar_date = report.meta.scan_date
        # NOTE (OQ1 / D-01): the find_prior_sidecar future-exclusion guard is
        # DROPPED here on purpose — today's sidecar is the one we draft from.
        # ``>=`` (not ``>``) makes a same-day tie resolve toward the later
        # candidate — safe here because the iteration order is mtime-ascending,
        # so "later candidate" means "newest-written file" (WR-02).
        if best_date is None or sidecar_date >= best_date:
            best_date = sidecar_date
            best_path = candidate
    return best_path


def load_scan_report(path: Path):
    """Parse a sidecar into a ScanReport, or ``None`` on hostile input.

    NEVER raises (Security V5 — the sidecar is untrusted hand-editable input).
    Returns ``None`` on the same exception set ``find_latest_sidecar`` skips on.
    """
    from repo_audit.schema.report import ScanReport

    try:
        return ScanReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (ValidationError, json.JSONDecodeError, OSError, ValueError):
        return None


def load_latest_sidecar(repo_path: Path):
    """Load the most-recent (today-inclusive) sidecar as a ScanReport.

    The public entry point the draft builder and CLI consume. Raises
    ``NoSidecarError`` (clear, actionable) when none exists; WARNS (does not
    raise) when the selected sidecar is older than ``STALE_AFTER_DAYS`` but
    still returns it (D-01 staleness disclosure — a stale finding set is still
    actionable).

    Raises:
        NoSidecarError: when no usable sidecar exists for the repo.
    """
    path = find_latest_sidecar(repo_path)
    if path is None:
        raise NoSidecarError(
            "No state report sidecar found under docs/state-reports/. "
            "Run `repo-audit scan` first to produce one, then re-run `repo-audit issues`."
        )
    report = load_scan_report(path)
    if report is None:
        # The selected path was the freshest by date but is unparseable in
        # isolation (race / truncation between glob and read). Treat as no
        # usable sidecar rather than crashing.
        raise NoSidecarError(
            f"The most-recent sidecar ({path.name}) could not be parsed. "
            "Re-run `repo-audit scan` to regenerate a valid state report."
        )

    age_days = (date.today() - report.meta.scan_date).days
    if age_days > STALE_AFTER_DAYS:
        warnings.warn(
            f"State report sidecar is stale ({age_days} days old, "
            f"scan_date={report.meta.scan_date.isoformat()}); proceeding anyway. "
            "Re-run `repo-audit scan` for a fresh finding set.",
            stacklevel=2,
        )
    return report


__all__ = [
    "NoSidecarError",
    "STALE_AFTER_DAYS",
    "find_latest_sidecar",
    "load_scan_report",
    "load_latest_sidecar",
]
