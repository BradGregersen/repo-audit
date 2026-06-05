"""SAST FeedProvenance builder (D-10-02) — the runtime-fetched ruleset stamp.

``build_sast_provenance`` turns a :class:`SastResult` into the reproducibility
stamp ``ReportMeta.feed_provenance`` carries (Plan 07-01 defined the model),
mirroring the Phase-7 ``sca/provenance.build_feed_provenance`` precedent. Exactly
ONE :class:`FeedProvenance` entry is emitted when the Semgrep run succeeded; an
unavailable/timed-out run contributes NO entry (nothing reproducible to stamp).

D-10-02 RUNTIME-FETCH posture (10-RESEARCH Pitfall 2):

    Semgrep registry packs (``p/owasp-top-ten``, ``p/secrets``, ``p/react``, …)
    are fetched LIVE from the registry at scan time — there is NO durable local
    snapshot the way the Phase-7 osv/grype vuln-DB has one. So ``db_snapshot_date``
    is honestly ``None`` (the registry has no per-run build date we capture); the
    run is reproducible BY-RECORD — the Semgrep VERSION (``scanner_version``) plus
    the scan DATE (``queried_at``) are the reproducibility anchor, exactly as the
    Phase-7 vuln-DB stamp records scanner version + snapshot date.

    A pinned/offline ruleset cache (the equivalent of the Phase-7 pinned vuln-DB)
    is DEFERRED to a future phase per D-10-02; until then ``db_snapshot_date=None``
    is the honest marker that this feed is runtime-fetched, not snapshot-pinned.

Honesty rules (deterministic collectors own all numbers):

    * ``db_snapshot_date`` — always ``None`` (runtime-fetch, no durable snapshot).
    * ``advisory_count`` — always ``None`` (Semgrep reports no clean rule total we
      stamp; ship None over an invented number, matching the SCA stamp).
    * ``queried_at`` — the caller's scan wall-clock; lives ONLY here, never on a
      Finding (Pitfall 7 / SC-5 bit-identity).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from repo_audit.adapters.sast.semgrep import SastResult
from repo_audit.schema.report import FeedProvenance

_SAST_FEED = "semgrep-registry"
_SAST_SCANNER = "semgrep"


def build_sast_provenance(
    result: SastResult,
    *,
    queried_at: datetime,
) -> list[FeedProvenance]:
    """Build the SAST FeedProvenance list (one entry on a successful run).

    Args:
        result: the :class:`SastResult` from ``collect_semgrep``.
        queried_at: the scan wall-clock timestamp (header-only metadata; never
            stamped onto a Finding — Pitfall 7).

    Returns:
        ``[entry]`` when ``result.status == "ok"`` — a single FeedProvenance with
        ``feed="semgrep-registry"``, ``scanner="semgrep"``, the SARIF driver
        version (or ``"unknown"``), ``db_snapshot_date=None`` (the honest
        runtime-fetch marker, D-10-02), and ``advisory_count=None``. ``[]`` when
        the run was unavailable/timed-out — there is nothing reproducible to
        stamp.
    """
    if result.status != "ok":
        return []

    return [
        FeedProvenance(
            feed=_SAST_FEED,
            scanner=_SAST_SCANNER,
            scanner_version=result.scanner_version or "unknown",
            db_snapshot_date=None,
            queried_at=queried_at,
            advisory_count=None,
        )
    ]


class CodeQlProvenance(BaseModel):
    """The license-posture stamp for a CodeQL run (DSAST-01 / D-16-08).

    Records under WHICH use-rights ground CodeQL was run so the report is
    auditable ("under which right was CodeQL run?"), not merely gated. The
    ``ground`` and ``note`` are deterministic — derived verbatim from the
    user's attested config, never invented.
    """

    model_config = ConfigDict(extra="forbid")

    ground: str
    note: str


def build_codeql_provenance(
    *,
    status: str,
    use_rights: Optional[str],
) -> list[CodeQlProvenance]:
    """Build the CodeQL use-rights provenance (one entry on a successful run).

    Mirrors :func:`build_sast_provenance`'s discipline: exactly ONE entry when
    the run succeeded AND a use-rights ground was attested; ``[]`` otherwise (an
    unavailable/timed-out run, or — defensively — a success with no ground,
    contributes no entry, never inventing a right).

    Args:
        status: the CodeQL ``AdapterResult.status`` (``"ok"`` on success).
        use_rights: the attested ground (``oss``/``ghas``/``personal-own-code``)
            the run was authorised under; ``None`` if absent.

    Returns:
        ``[CodeQlProvenance]`` stamping the chosen ground when ``status == "ok"``
        and a ground is present; ``[]`` otherwise.
    """
    if status != "ok" or use_rights is None:
        return []

    return [
        CodeQlProvenance(
            ground=use_rights,
            note=f"ran CodeQL under {use_rights} attestation",
        )
    ]


__all__ = [
    "CodeQlProvenance",
    "build_codeql_provenance",
    "build_sast_provenance",
]
