"""RLS provenance — the D-08-09/16 reproducibility stamp (Plan 08-05).

Phase 8's analogue of the Phase 7 ``FeedProvenance`` discipline, but recorded as
a structured LEDGER NOTE rather than a ``FeedProvenance`` entry (that model is
vuln-feed-shaped — feed/scanner/db_snapshot_date — and does not fit a tool/image/
SHA stamp). :func:`build_rls_provenance` assembles the dict the scope ledger
records so any RLS finding can be attributed to a reproducible toolchain:

    * ``splinter_sha``     — the upstream commit splinter.sql is fetched from
      (the lint set's exact version), returned by :func:`read_splinter_sha`.
    * ``pgrls_version`` / ``squawk_version`` — the additive-layer tool versions.
    * ``image_ref``        — the pinned ``supabase/postgres`` ``tag@sha256:digest``
      the ephemeral DB stood up from (D-08-09 / FND-03 reproducibility).
    * ``layout``           — the matched migration layout (``supabase/migrations``
      / ``legacy-numbered-sql`` / ``none``).
    * ``runtime_posture``  — one of the five honest postures: the runtime test was
      not run (not opted in / no creds), or ran (pass / leak / error). This is the
      D-08-05 honest not-run disclosure made machine-readable.

Pure + never-raising: :func:`read_splinter_sha` returns the pinned fetch commit,
a constant, so it needs no file and cannot fail.
"""
from __future__ import annotations

from typing import Literal

from repo_audit.adapters.supabase.splinter_fetch import SPLINTER_COMMIT

# The five honest runtime postures (D-08-05). "not_run_*" carry NO enforcement
# claim; "run_*" reflect the actually-executed two-account probe's verdict.
RuntimePosture = Literal[
    "not_run_not_opted_in",
    "not_run_no_creds",
    "run_pass",
    "run_leak",
    "run_error",
]

# Sentinel for a missing provenance field — honest "unknown", never a fake.
_UNKNOWN_SHA = "unknown"


def read_splinter_sha() -> str:
    """Return the upstream commit splinter.sql is fetched from.

    splinter.sql is downloaded at a pinned commit and verified against a pinned
    sha256 (see ``splinter_fetch``), so the lint set's version is that constant.

    Returns:
        The 40-hex commit SHA.
    """
    return SPLINTER_COMMIT


def build_rls_provenance(
    *,
    splinter_sha: str,
    pgrls_version: str,
    squawk_version: str,
    image_ref: str,
    layout: str,
    runtime_posture: str,
) -> dict[str, str]:
    """Assemble the RLS reproducibility stamp as a structured ledger payload.

    This is the D-08-09/16 reproducibility stamp: a flat ``dict[str, str]`` the
    scope ledger records so a finding can be reproduced against the same lint set
    (splinter SHA), the same additive-tool versions, the same pinned DB image,
    the same discovered migration layout, and with the same runtime posture.

    Args:
        splinter_sha: the commit splinter.sql is fetched from.
        pgrls_version: the installed pgrls version (or a floor pin).
        squawk_version: the installed squawk version (or ``"unknown"``).
        image_ref: the pinned ``supabase/postgres`` ``tag@sha256:digest``.
        layout: the matched migration layout.
        runtime_posture: one of the five :data:`RuntimePosture` values.

    Returns:
        The provenance dict (all string-valued; safe to fold into ledger notes).
    """
    return {
        "splinter_sha": splinter_sha,
        "pgrls_version": pgrls_version,
        "squawk_version": squawk_version,
        "image_ref": image_ref,
        "layout": layout,
        "runtime_posture": runtime_posture,
    }


def provenance_note(provenance: dict[str, str]) -> str:
    """Render the provenance dict as one human-readable scope-ledger note line."""
    return (
        "RLS provenance — "
        f"splinter@{provenance.get('splinter_sha', _UNKNOWN_SHA)}; "
        f"pgrls {provenance.get('pgrls_version', 'unknown')}; "
        f"squawk {provenance.get('squawk_version', 'unknown')}; "
        f"image {provenance.get('image_ref', 'unknown')}; "
        f"layout={provenance.get('layout', 'none')}; "
        f"runtime={provenance.get('runtime_posture', 'unknown')}"
    )


__all__ = [
    "RuntimePosture",
    "build_rls_provenance",
    "provenance_note",
    "read_splinter_sha",
]
