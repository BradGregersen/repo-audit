"""Deterministic SARIF severity -> Severity policy (SC-2, D-06-01).

A SARIF result carries two independent severity signals:

1. ``result.level`` — the coarse SARIF kind: ``error`` / ``warning`` /
   ``note`` / ``none`` (or absent). This is what every SARIF tool sets.
2. ``rule.properties.security-severity`` — an optional CVSS-style numeric
   string (``"0.0"`` .. ``"10.0"``) that security analysers (CodeQL, Semgrep,
   osv-scanner, …) attach to encode a *finer* severity than the 4-value level.

``map_severity`` folds both onto the 5-value :data:`Severity` literal with a
fixed precedence so the same SARIF doc always yields the same severity
(reproducibility — the LLM never touches these numbers).

Precedence (strongest signal first)
-----------------------------------
1. **security-severity numeric band** — if present AND parseable as a float
   AND ``> 0.0``, the band below decides the severity outright. This is the
   most specific security signal and overrides BOTH the level and any
   per-tool ``severity_map`` entry.
2. **per-tool severity_map** — a caller-supplied ``{level: Severity}`` dict
   (resolved AT CALL TIME, never read at module load — Phase 3
   ``test_overrides_resolved_at_call_time_not_module_load`` precedent). Lets a
   tool promote/demote its own levels declaratively (D-06-04 adapter.yaml).
3. **default faithful level map** — the table below (D-06-01).

security-severity numeric bands (de-facto SARIF / CodeQL convention)
--------------------------------------------------------------------
====================  ==========
score range           Severity
====================  ==========
9.0 – 10.0            critical
7.0 – 8.9             major
4.0 – 6.9             minor
0.1 – 3.9             info
0.0 / unparseable     (fall through to level/map — never crash)
====================  ==========

default faithful level map (D-06-01)
------------------------------------
====================  ==========
result.level          Severity
====================  ==========
error                critical
warning              major
note                 minor
none                 info
(missing)            info        (faithful floor: absent level means the rule
                                  default applies; lacking rule metadata we
                                  floor at info rather than inventing severity)
====================  ==========
"""
from __future__ import annotations

from repo_audit.schema.enums import Severity

# D-06-01 default faithful level -> Severity table.
_DEFAULT_LEVEL_MAP: dict[str, Severity] = {
    "error": "critical",
    "warning": "major",
    "note": "minor",
    "none": "info",
}

# Faithful floor when no level signal is present at all.
_MISSING_LEVEL_SEVERITY: Severity = "info"


def _band_for_security_severity(raw: str | float | None) -> Severity | None:
    """Map a security-severity score to a Severity band, or None to fall through.

    Returns None when the score is absent, unparseable, or 0.0 (no signal).
    """
    if raw is None:
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    if score <= 0.0:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "major"
    if score >= 4.0:
        return "minor"
    return "info"


def map_severity(
    level: str | None,
    security_severity: str | float | None,
    severity_map: dict[str, Severity],
) -> Severity:
    """Map a SARIF (level, security-severity) pair onto a Severity literal.

    Args:
        level: ``result.level`` (``error``/``warning``/``note``/``none`` or None).
        security_severity: ``rule.properties.security-severity`` numeric string
            (or float / None). When present and ``> 0.0`` it OVERRIDES the level.
        severity_map: caller-supplied per-tool ``{level: Severity}`` overrides,
            resolved at call time. Wins over the default table; loses to a
            present security-severity band.

    Returns:
        One of ``"blocker" | "critical" | "major" | "minor" | "info"``.
    """
    # 1. security-severity band is the strongest signal.
    band = _band_for_security_severity(security_severity)
    if band is not None:
        return band

    # 2. per-tool override (call-time).
    if level is not None and level in severity_map:
        return severity_map[level]

    # 3. default faithful level map.
    if level is None:
        return _MISSING_LEVEL_SEVERITY
    return _DEFAULT_LEVEL_MAP.get(level, _MISSING_LEVEL_SEVERITY)
