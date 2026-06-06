"""Opt-in FIRST.org EPSS reader — the ONLY network touch in Phase 18 (T-18-05).

EPSS (Exploit Prediction Scoring System) is a raise-only multiplier within band
(D-18-02): a present score scales the composite, an ABSENT score is the neutral
1.0 baseline — NEVER a penalty relative to having no EPSS data at all (Pitfall 4 /
D-18-02).

The egress is opt-in and OFF by default (T-18-05): when ``enabled`` is False,
``epss_lookup`` returns ``None`` IMMEDIATELY and the ``urllib`` import never runs —
the default scan path pulls in NO network module. The ``urllib`` import is kept
LOCAL to the enabled branch so a default-path import graph never reaches it (the
deps.dev WR-01 / dast structural-gate precedent).

Every failure mode (opt-out / timeout / unreachable / non-200 / parse error /
missing data) → ``None`` (neutral). Combined with ``run_synthesis``'s never-raise
wrap, a slow or down EPSS API can never break or hang a scan (T-18-07).
"""
from __future__ import annotations

import json

# The FIRST.org EPSS v1 endpoint. A single-CVE query: ?cve=CVE-YYYY-NNNNN.
_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"


def epss_lookup(
    cve: str,
    *,
    enabled: bool,
    timeout_seconds: int = 15,
) -> float | None:
    """Return the EPSS score (0..1) for ``cve``, or ``None`` (neutral) when absent.

    Args:
        cve: the CVE id to query (e.g. ``CVE-2021-44228``).
        enabled: the opt-in egress gate. When False, returns ``None`` immediately
            WITHOUT importing or touching the network (the default-OFF path,
            T-18-05).
        timeout_seconds: wall-clock cap on the urllib GET (T-18-07).

    Returns:
        The float EPSS score on success, else ``None`` (neutral — NEVER a penalty,
        D-18-02). NEVER raises: any timeout / unreachable / non-200 / parse failure
        degrades to ``None``.
    """
    # The opt-in gate: default path returns None WITHOUT importing urllib, so the
    # default scan import graph never reaches the network module (T-18-05).
    if not enabled:
        return None
    if not cve:
        return None

    # urllib import is LOCAL to the enabled branch — the structural egress gate.
    import urllib.request  # noqa: PLC0415 — local on purpose (default path never imports network)
    from urllib.parse import urlencode

    url = f"{_EPSS_ENDPOINT}?{urlencode({'cve': cve})}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as resp:  # noqa: S310 — fixed https endpoint
            if getattr(resp, "status", 200) != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
        data = payload.get("data") or []
        if not data:
            return None
        raw = data[0].get("epss")
        if raw is None:
            return None
        # EPSS is a probability in [0,1]. Validate the network-supplied float and
        # degrade to neutral (None) on anything out of range — a hostile/garbage
        # response (e.g. "1e9" or a negative) must NEVER reach the multiplicative
        # composite, where it could arbitrarily inflate or zero a finding's priority
        # and break the raise-only / never-penalize contract (WR-05).
        val = float(raw)
        if not (0.0 <= val <= 1.0):
            return None
        return val
    except Exception:  # noqa: BLE001 — timeout/unreachable/parse → neutral, never breaks a scan
        return None


__all__ = ["epss_lookup"]
