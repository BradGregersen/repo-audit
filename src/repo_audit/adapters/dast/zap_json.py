"""ZAP ``-J`` JSON → Finding normalizer (DAST-01, Phase 16).

ZAP has no SARIF reporter (RESEARCH Pitfall 6) — the baseline scan emits a
ZAP-native JSON document via ``-J``. ``zap_json_to_findings`` is the per-tool
adapter that maps that document onto the SAME :class:`Finding` shape every other
lane produces, mirroring ``sarif/parser.py::_result_to_finding`` with two
deliberate divergences:

  1. ``evidence_type`` is the HARD-CODED literal ``"heuristic"`` — a passive
     baseline scan is a heuristic observation, NOT a runtime exploit proof
     (D-16-12, SAFE-01). The literal is fixed in code (never derived from the
     tool output), so this lane can NEVER emit ``evidence_type='runtime'`` (that
     tag is reserved for the Phase-8 Supabase two-account test). The downstream
     ``run_dast`` post-pass guard is a second, defensive backstop.
  2. Severity is mapped from ZAP's ``riskcode`` band (3/2/1/0), NOT a SARIF
     ``level``. The candidate cap (06-01 contract / SCH-04) then applies exactly
     as in the SARIF parser: a High riskcode's faithful ``critical`` is demoted
     to ``major`` at ``confidence='candidate'`` with a Phase-17 promotion
     breadcrumb; the faithful severity is preserved in
     ``evidence.parsed_value``. A candidate+critical Finding is structurally
     impossible here, same as everywhere else.

ZAP ``-J`` JSON shape (fixture ``tests/adapters/fixtures/zap/baseline.json``)::

    {"site": [{"alerts": [{"alert", "riskcode", "confidence", "url", "desc",
                           "pluginid", ...}]}]}

Defensive: a missing/empty/non-dict document, an absent ``site`` / ``alerts``,
or an alert with missing keys → ``[]``. This function NEVER raises (D-25): a
broken or hostile tool document must not break the scan.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.enums import Severity
from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "zap"
_DIMENSION = "security"

# ZAP riskcode → faithful severity band (RESEARCH §"ZAP baseline via Docker").
#   3 = High → critical (then candidate-capped to major)
#   2 = Medium → major
#   1 = Low → minor
#   0 = Informational → info
_RISKCODE_SEVERITY: dict[str, Severity] = {
    "3": "critical",
    "2": "major",
    "1": "minor",
    "0": "info",
}
_FALLBACK_SEVERITY: Severity = "info"

# SCH-04 forbids confidence='candidate' + severity in {critical, blocker}. Every
# ZAP Finding sits at confidence='candidate', so a faithful critical (riskcode 3)
# is DEMOTED to major before construction — mirrors sarif/parser.py's cap.
_CAPPED_SEVERITIES: frozenset[Severity] = frozenset({"critical", "blocker"})
_CANDIDATE_CAP: Severity = "major"
_CAPPED_CRITICAL_CAVEAT = (
    "zap reported {faithful_severity} (riskcode {riskcode}); capped at major at "
    "confidence=candidate per SCH-04 — pending Phase 17 corroboration."
)


def _alert_to_finding(alert: dict[str, Any]) -> Finding | None:
    """Map one ZAP alert dict → one Finding. Returns None on a malformed alert.

    Hard-codes ``evidence_type='heuristic'`` (never derived from tool output),
    applies the candidate severity cap, and preserves the faithful severity +
    riskcode in ``evidence.parsed_value`` as the Phase-17 promotion breadcrumb.
    """
    if not isinstance(alert, dict):
        return None

    riskcode = str(alert.get("riskcode", "")).strip()
    faithful_severity: Severity = _RISKCODE_SEVERITY.get(riskcode, _FALLBACK_SEVERITY)

    # Candidate cap (mirror sarif/parser.py): a faithful critical/blocker is
    # demoted to major BEFORE the single Finding(...) construction — never
    # build-then-retry on a validation error.
    confidence_caveat: str | None = None
    if faithful_severity in _CAPPED_SEVERITIES:
        severity: Severity = _CANDIDATE_CAP
        confidence_caveat = _CAPPED_CRITICAL_CAVEAT.format(
            faithful_severity=faithful_severity,
            riskcode=riskcode or "n/a",
        )
    else:
        severity = faithful_severity

    name = str(alert.get("alert") or alert.get("name") or "")
    desc = str(alert.get("desc") or "")
    snippet = f"{name}: {desc}".strip(": ").strip() if desc else name

    evidence = Evidence(
        tool=_SOURCE_TOOL,
        output_snippet=snippet,
        parsed_value={
            "rule_id": str(alert.get("pluginid", "")),
            "url": str(alert.get("url", "")),
            "riskcode": riskcode,
            "zap_confidence": str(alert.get("confidence", "")),
            # Preserve the pre-cap faithful severity so Phase 17 can promote.
            "faithful_severity": faithful_severity,
        },
        line_range=None,
    )

    return Finding(
        dimension=_DIMENSION,  # type: ignore[arg-type]
        severity=severity,
        file=None,
        line=None,
        evidence=evidence,
        # HARD-CODED literal — a baseline scan is heuristic, never runtime/static.
        evidence_type="heuristic",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        rule_id=str(alert.get("pluginid", "")),
        confidence_caveat=confidence_caveat,
    )


def zap_json_to_findings(doc: Any) -> list[Finding]:
    """Normalize a ZAP ``-J`` JSON document → ``list[Finding]`` @ heuristic.

    Args:
        doc: the parsed ZAP JSON (``{"site": [{"alerts": [...]}]}``). A
            missing/empty/non-dict value, or any structural surprise, yields
            ``[]``.

    Returns:
        One Finding per ``site[].alerts[]`` entry at ``dimension='security'``,
        ``evidence_type='heuristic'``, ``confidence='candidate'``,
        ``source_tool='zap'`` — riskcode-mapped + candidate-capped. NEVER raises;
        NEVER emits ``evidence_type='runtime'``.
    """
    findings: list[Finding] = []
    if not isinstance(doc, dict):
        return findings

    sites = doc.get("site")
    if not isinstance(sites, list):
        return findings

    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            try:
                finding = _alert_to_finding(alert)
            except Exception:  # noqa: BLE001 — a malformed alert never breaks a scan
                finding = None
            if finding is not None:
                findings.append(finding)

    return findings


__all__ = ["zap_json_to_findings"]
