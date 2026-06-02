"""RLS provenance — the D-08-09/16 reproducibility stamp (Plan 08-05).

Phase 8's analogue of the Phase 7 ``FeedProvenance`` discipline, but recorded as
a structured LEDGER NOTE rather than a ``FeedProvenance`` entry (that model is
vuln-feed-shaped — feed/scanner/db_snapshot_date — and does not fit a tool/image/
SHA stamp). :func:`build_rls_provenance` assembles the dict the scope ledger
records so any RLS finding can be attributed to a reproducible toolchain:

    * ``splinter_sha``     — the vendored splinter.sql commit SHA (the lint set's
      exact version), parsed from the vendored file's header line by
      :func:`read_splinter_sha`.
    * ``pgrls_version`` / ``squawk_version`` — the additive-layer tool versions.
    * ``image_ref``        — the pinned ``supabase/postgres`` ``tag@sha256:digest``
      the ephemeral DB stood up from (D-08-09 / FND-03 reproducibility).
    * ``layout``           — the matched migration layout (``supabase/migrations``
      / ``legacy-numbered-sql`` / ``none``).
    * ``runtime_posture``  — one of the five honest postures: the runtime test was
      not run (not opted in / no creds), or ran (pass / leak / error). This is the
      D-08-05 honest not-run disclosure made machine-readable.

Pure + never-raising: :func:`read_splinter_sha` degrades to a sentinel string
when the vendored file / header line is missing rather than crashing the scan.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

# The five honest runtime postures (D-08-05). "not_run_*" carry NO enforcement
# claim; "run_*" reflect the actually-executed two-account probe's verdict.
RuntimePosture = Literal[
    "not_run_not_opted_in",
    "not_run_no_creds",
    "run_pass",
    "run_leak",
    "run_error",
]

# The vendored splinter.sql lives beside the package's vendor tree. Header line 1
# is ``-- splinter.sql vendored from supabase/splinter @ <40-hex-sha>``.
_SPLINTER_SQL_PATH = (
    Path(__file__).resolve().parents[2] / "vendor" / "splinter" / "splinter.sql"
)

# Matches the 40-hex commit SHA after the ``@`` in the vendored header line.
_SHA_RE = re.compile(r"@\s*([0-9a-fA-F]{40})")

# Sentinel when the header / file is unreadable — honest "unknown", never a fake.
_UNKNOWN_SHA = "unknown"


def read_splinter_sha(path: Path | None = None) -> str:
    """Parse the vendored splinter.sql header for its pinned commit SHA.

    The vendored file's first header line records the exact upstream commit the
    lint set was fetched from (``-- splinter.sql vendored from supabase/splinter
    @ <sha>``). Returns that 40-hex SHA, or :data:`_UNKNOWN_SHA` when the file or
    header line is absent (never raises — provenance must degrade honestly).

    Args:
        path: optional override for the vendored splinter.sql (tests).

    Returns:
        The 40-hex SHA string, or ``"unknown"`` when it cannot be read.
    """
    sql_path = path or _SPLINTER_SQL_PATH
    try:
        # Only the first few header lines are needed; read a bounded prefix.
        with sql_path.open("r", encoding="utf-8") as fh:
            for _ in range(8):
                line = fh.readline()
                if not line:
                    break
                match = _SHA_RE.search(line)
                if match is not None:
                    return match.group(1).lower()
    except OSError:
        return _UNKNOWN_SHA
    return _UNKNOWN_SHA


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
        splinter_sha: the vendored splinter.sql commit SHA.
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
