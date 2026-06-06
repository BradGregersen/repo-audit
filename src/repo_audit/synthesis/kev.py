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


def is_kev(finding: "Finding", kev_set: frozenset[str] | set[str] = KEV_SET) -> bool:
    """Return True iff this finding's CVE is in the KEV catalog.

    A non-SCA finding (no ``cve`` in ``parsed_value``) → False. The CVE is keyed
    via ``normalize_cve`` so casing differences never miss a match.
    """
    cve = finding_cve(finding)
    if cve is None:
        return False
    return normalize_cve(cve) in kev_set


__all__ = ["KEV_SET", "load_kev_set", "finding_cve", "is_kev"]
