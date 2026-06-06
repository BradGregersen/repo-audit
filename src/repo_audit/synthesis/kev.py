"""Bundled offline CISA KEV loader + per-finding KEV lookup (SYN-01, T-18-06).

The KEV catalog is the ``band=1`` lexicographic top-band signal (a CVE that is in
CISA's Known Exploited Vulnerabilities list sorts above every non-KEV finding,
D-18-02). The catalog is VENDORED at
``vendor/kev/known_exploited_vulnerabilities.json`` (SHA-256-pinned, PROVENANCE
recorded) so the default scan KEV top-band works with ZERO network egress
(T-18-06). The default path NEVER fetches; ``repo-audit scan --refresh-kev`` is the sole
re-fetch path.

The set is keyed via ``normalize_cve`` (``cve.strip().upper()`` — the SAME key the
SCA enrichment lane uses), so a finding's ``parsed_value["cve"]`` matches the
catalog regardless of source casing. A non-SCA finding (no ``cve`` in its
``parsed_value``) is never in KEV → ``False``.

Loaded via stdlib ``json`` only — this is a default-path module, so it NEVER
imports the network reader (the egress gate lives in ``epss.py``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from repo_audit.adapters.sca.enrich import normalize_cve

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding

# The vendored, SHA-256-pinned snapshot (see vendor/kev/PROVENANCE). Resolved
# relative to this module so it ships inside the wheel.
_VENDOR_KEV = (
    Path(__file__).resolve().parent.parent
    / "vendor"
    / "kev"
    / "known_exploited_vulnerabilities.json"
)


def load_kev_set(path: Path | str | None = None) -> frozenset[str]:
    """Build the normalized KEV CVE set from the bundled snapshot.

    Args:
        path: optional override for the catalog file (defaults to the vendored
            snapshot). The file must parse as ``{"vulnerabilities": [{"cveID": ...}]}``.

    Returns:
        A ``frozenset`` of ``normalize_cve(cveID)`` ids. NEVER raises: a missing /
        unreadable / malformed catalog degrades to an EMPTY set (the KEV band is
        simply unavailable — every finding stays band 0; the scan completes).
    """
    catalog = Path(path) if path is not None else _VENDOR_KEV
    try:
        doc = json.loads(catalog.read_text(encoding="utf-8"))
        vulns = doc.get("vulnerabilities") or []
        return frozenset(
            normalize_cve(v["cveID"]) for v in vulns if isinstance(v, dict) and v.get("cveID")
        )
    except Exception:  # noqa: BLE001 — a missing/broken catalog never breaks a scan
        return frozenset()


# Module-level default set, built once from the bundled snapshot. Callers that do
# not pass an explicit catalog reuse this (the common default-scan path).
KEV_SET: frozenset[str] = load_kev_set()


def finding_cve(finding: "Finding") -> str | None:
    """Read a finding's CVE id from ``evidence.parsed_value['cve']`` (the literal
    key osv-scanner/grype emit). Returns None for a non-SCA finding (no cve)."""
    parsed = (getattr(finding.evidence, "parsed_value", None) or {})
    cve = parsed.get("cve")
    return cve if isinstance(cve, str) and cve else None


# The upstream CISA KEV feed (recorded in vendor/kev/PROVENANCE). The ONLY URL the
# explicit --refresh-kev step fetches; the default scan path NEVER reaches it.
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def refresh_kev_snapshot(*, timeout_seconds: int = 30) -> str:
    """Re-fetch the CISA KEV feed into ``vendor/kev/`` and restamp PROVENANCE.

    The SOLE path that advances the pinned KEV snapshot (the ``--refresh-kev``
    step, mirroring ``--refresh-vuln-db``). NEVER invoked on a default scan
    (zero-egress default, D-18-06). The ``urllib`` import is LOCAL to this explicit
    refresh path so the default-scan import graph never reaches the network.

    Args:
        timeout_seconds: wall-clock cap on the feed GET.

    Returns:
        The SHA-256 of the freshly written snapshot.

    Raises:
        Propagates network/IO errors to the caller — refresh is an explicit,
        user-invoked step (unlike the never-raise default scan path), so a failed
        fetch surfaces loudly rather than silently shipping a stale snapshot.
    """
    import datetime as _dt
    import hashlib
    import urllib.request  # noqa: PLC0415 — local to the explicit refresh step

    with urllib.request.urlopen(KEV_FEED_URL, timeout=timeout_seconds) as resp:  # noqa: S310 — fixed gov https feed
        raw = resp.read()

    # Validate it parses as the expected KEV shape before overwriting the pin.
    doc = json.loads(raw.decode("utf-8"))
    if "vulnerabilities" not in doc:
        raise ValueError("KEV feed missing 'vulnerabilities' — refusing to restamp")

    _VENDOR_KEV.write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    provenance = _VENDOR_KEV.parent / "PROVENANCE"
    today = _dt.date.today().isoformat()
    catalog_version = str(doc.get("catalogVersion", "unknown"))
    provenance.write_text(
        "# Vendored CISA Known Exploited Vulnerabilities (KEV) snapshot\n"
        "#\n"
        "# Re-fetched by `repo-audit scan --refresh-kev` (the SOLE re-fetch path).\n"
        "# The default scan path NEVER auto-fetches this file (zero egress, T-18-06).\n"
        "\n"
        f"source_url:  {KEV_FEED_URL}\n"
        f"fetch_date:  {today}\n"
        f"catalog_version: {catalog_version}\n"
        "file:        known_exploited_vulnerabilities.json\n"
        f"sha256:      {sha}\n"
        "license:     U.S. public domain (CISA, https://www.cisa.gov/about/site-policies)\n",
        encoding="utf-8",
    )
    return sha


def is_kev(finding: "Finding", kev_set: frozenset[str] | set[str] = KEV_SET) -> bool:
    """Return True iff this finding's CVE is in the KEV catalog.

    A non-SCA finding (no ``cve`` in ``parsed_value``) → False. The CVE is keyed
    via ``normalize_cve`` so casing differences never miss a match.
    """
    cve = finding_cve(finding)
    if cve is None:
        return False
    return normalize_cve(cve) in kev_set


__all__ = [
    "KEV_SET",
    "KEV_FEED_URL",
    "load_kev_set",
    "refresh_kev_snapshot",
    "finding_cve",
    "is_kev",
]
