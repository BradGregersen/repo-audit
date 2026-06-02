"""MOB-03 Tier-3a (9-T3a) — MobSF Docker static client + redacting mapper (Plan 09-03).

Opt-in (``--mobsf``) binary-level static analysis of a SHIPPED debug APK. MobSF
catches secrets/issues that source scanning misses because they only exist in the
built artifact (resource strings, smali, packaged config). This module is the
Docker REST client + the report mapper.

Two seams, mirroring the Phase-7/8 native-JSON precedent (osv/grype/squawk):

  * :func:`map_mobsf_report` — maps MobSF's ``StaticAnalyzerAndroid`` ``report_json``
    (NOT SARIF — a bespoke shape with ``secrets`` / ``possible_secrets`` lists and a
    ``findings`` map) to candidate/static security Findings. This is the MOST
    DANGEROUS untrusted-output boundary in the phase: ``report_json`` carries RAW
    secret VALUES. EVERY such value is routed through the redaction chokepoint
    (:func:`_redact_span` → ``[REDACTED:N]``) BEFORE a Finding is constructed —
    the raw string NEVER enters ``output_snippet`` or ``parsed_value`` (T-09-04 /
    SCH-08 defense-in-depth).

  * :func:`collect_mobsf` — the Docker lifecycle: start MobSF behind ``run_tool``
    (FND-04, shell=False) with a per-run ``MOBSF_API_KEY`` generated via
    ``secrets.token_hex`` (NEVER scraped from logs/UI, T-09-09), upload → scan →
    pull ``report_json`` → delete_scan over stdlib ``urllib`` (no new HTTP dep),
    then a guaranteed ``try/finally`` ``docker stop`` teardown (T-09-03, Pitfall 3)
    even on an HTTP error. Absent Docker / absent APK / any HTTP error degrades to
    ``unavailable`` / ``timeout`` and NEVER hangs.

The ``image_ref`` (a pinned ``…@sha256:<digest>``) is passed IN by Plan 05 — this
module accepts it as a parameter and never hard-codes a digest (Plan 05 owns the
pin; T-09-10). Registration (``@register_adapter("mobile")``) is also Plan 05's.
"""
from __future__ import annotations

import json
import secrets
import socket
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.supabase.footguns import _redact_span
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.enums import Severity
from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "mobsf"
_SOURCE_ADAPTER = "mobile"
_DIMENSION = "security"

# MobSF finding ``severity`` -> mapped Severity. "high" is capped at "major"
# (SCH-04 forbids candidate + {critical, blocker}; only Phase-17 corroboration
# may promote). Unknown/absent levels default to "info".
_MOBSF_SEVERITY: dict[str, Severity] = {
    "high": "major",
    "warning": "minor",
    "info": "info",
}
_DEFAULT_SEVERITY: Severity = "info"

# rule_id for the redacted hardcoded-secret findings (the secrets/possible_secrets
# lists). Distinct from the slugified per-finding rule ids below.
_SECRET_RULE_ID = "mobsf_hardcoded_secret"

# Metadata keys we are willing to copy onto parsed_value from a MobSF finding's
# ``metadata`` block. We DELIBERATELY do not copy metadata blindly — only these
# describe the rule (severity/taxonomy), never a value that could carry a secret.
_SAFE_METADATA_KEYS: frozenset[str] = frozenset(
    {"cvss", "cwe", "owasp-mobile", "masvs"}
)


def _severity_for(level: object) -> Severity:
    """Map a MobSF severity string to a capped Severity (default info)."""
    return _MOBSF_SEVERITY.get(str(level).strip().lower(), _DEFAULT_SEVERITY)


def _slugify_rule_id(title: str) -> str:
    """Turn a MobSF finding title into a stable snake_case rule_id."""
    out: list[str] = []
    prev_us = False
    for ch in title.strip().lower():
        if ch.isalnum():
            out.append(ch)
            prev_us = False
        elif not prev_us:
            out.append("_")
            prev_us = True
    slug = "".join(out).strip("_")
    return slug or "mobsf_finding"


def _secret_finding(raw_secret: str, source_key: str) -> Finding:
    """Build ONE redacted Finding for a raw secret string from report_json.

    The raw value is passed through :func:`_redact_span` → ``[REDACTED:N]`` and
    the literal NEVER enters ``output_snippet`` or ``parsed_value``. Only the
    LENGTH and provenance survive (T-09-04 / SCH-08 defense-in-depth).
    """
    redacted = _redact_span(raw_secret)
    recommendation = (
        "a hardcoded secret was detected in the APK; verify and rotate — "
        "value redacted. Cross-check the MOB-02 bundled-secrets pass; MobSF "
        "flags the presence of a secret-shaped string in the built artifact, "
        "not that the value is live."
    )
    caveat = (
        "MobSF static secret match in the built APK (value redacted at the "
        "adapter boundary); confirm the secret is real and reachable before "
        "acting."
    )
    return Finding(
        dimension=_DIMENSION,
        severity="major",  # SCH-04 candidate cap forbids critical/blocker
        file=None,
        line=None,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=f"hardcoded secret in APK {redacted}",
            parsed_value={
                "redacted_len": len(raw_secret),
                "source": source_key,
            },
        ),
        evidence_type="static",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id=_SECRET_RULE_ID,
        confidence_caveat=caveat,
    )


def _safe_metadata(metadata: object) -> dict[str, object]:
    """Copy ONLY the allowlisted taxonomy keys from a finding's metadata.

    MobSF ``metadata`` can carry a free-form ``description`` (and, defensively,
    anything else) — we never copy it blindly into ``parsed_value`` because it
    could echo a secret-bearing string. Only severity/taxonomy keys survive.
    """
    if not isinstance(metadata, dict):
        return {}
    return {k: v for k, v in metadata.items() if k in _SAFE_METADATA_KEYS}


def _issue_finding(title: str, body: object) -> Finding | None:
    """Map one entry of report_json["findings"] to a Finding (or None)."""
    if not isinstance(body, dict):
        return None
    severity = _severity_for(body.get("severity"))
    rule_id = _slugify_rule_id(title)

    # file/line from the first entry of the ``files`` map when present. MobSF's
    # ``files`` is a {path: location-hint} map; the path is the key. There is no
    # reliable line number in the static report shape, so line stays None.
    file_path: str | None = None
    files = body.get("files")
    if isinstance(files, dict) and files:
        first_key = next(iter(files))
        file_path = str(first_key)

    parsed_value: dict[str, object] = {
        "title": title,
        "severity": str(body.get("severity", "")),
    }
    parsed_value.update(_safe_metadata(body.get("metadata")))

    recommendation = (
        f"MobSF static analysis flagged '{title}' in the built APK; review the "
        "referenced artifact and verify the issue before acting (binary-level "
        "static signal, not runtime-confirmed)."
    )
    return Finding(
        dimension=_DIMENSION,
        severity=severity,
        file=file_path,
        line=None,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=f"mobsf: {title}",
            parsed_value=parsed_value,
        ),
        evidence_type="static",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id=rule_id,
    )


def map_mobsf_report(report_json: dict) -> list[Finding]:
    """Map a MobSF ``report_json`` document to redacted static security Findings.

    Consumes the ``StaticAnalyzerAndroid`` shape (NOT SARIF — a bespoke native
    JSON, mirroring the Phase-7/8 osv/grype/squawk native-JSON precedent):

      * ``secrets`` / ``possible_secrets`` / ``hardcoded_secrets`` — lists of RAW
        secret strings. Each becomes ONE Finding with the value REDACTED via
        :func:`_redact_span` → ``[REDACTED:N]`` BEFORE construction; the raw
        string NEVER reaches ``output_snippet`` or ``parsed_value`` (T-09-04).
        ``rule_id="mobsf_hardcoded_secret"``, ``severity="major"``.
      * ``findings`` — a ``{title: {severity, files, metadata}}`` map. Each maps
        through :data:`_MOBSF_SEVERITY` ("high"→major capped, "warning"→minor,
        "info"/unknown→info), ``rule_id`` = slugified title, file from the first
        ``files`` key. Only allowlisted taxonomy metadata is copied (never a raw
        ``description`` that could echo a secret).

    Every Finding: ``source_tool="mobsf"``, ``dimension="security"``,
    ``evidence_type="static"``, ``confidence="candidate"``, severity ≤ "major".
    Empty/missing keys → ``[]`` (never crashes).

    Args:
        report_json: the parsed MobSF report_json document.

    Returns:
        One :class:`Finding` per raw secret and per ``findings`` entry, all with
        every raw secret redacted at this boundary.
    """
    if not isinstance(report_json, dict):
        return []

    findings: list[Finding] = []

    # Raw-secret lists → redacted findings (the dangerous boundary).
    for source_key in ("secrets", "possible_secrets", "hardcoded_secrets"):
        raw_list = report_json.get(source_key) or []
        if not isinstance(raw_list, (list, tuple)):
            continue
        for raw_secret in raw_list:
            if not isinstance(raw_secret, str) or not raw_secret.strip():
                continue
            findings.append(_secret_finding(raw_secret, source_key))

    # The ``findings`` map → per-issue findings.
    issues = report_json.get("findings")
    if isinstance(issues, dict):
        for title, body in issues.items():
            finding = _issue_finding(str(title), body)
            if finding is not None:
                findings.append(finding)

    return findings


# Naming aliases — the Wave-0 test (_map_report) probes these names in order.
report_json_to_findings = map_mobsf_report
map_report_json = map_mobsf_report
map_mobsf_json = map_mobsf_report


__all__ = [
    "_MOBSF_SEVERITY",
    "map_mobsf_report",
    "report_json_to_findings",
    "map_report_json",
    "map_mobsf_json",
]
