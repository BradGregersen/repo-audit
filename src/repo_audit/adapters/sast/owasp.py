"""OWASP/CWE tag extraction — count-invariant Finding enrichment (Plan 10-02).

Semgrep carries OWASP + CWE categories on ``rule.properties.tags`` (e.g.
``["CWE-78: ...", "OWASP-A03:2021 - Injection", "security"]``), not on the
SARIF result. :func:`annotate_owasp` builds a ``{rule_id: tags}`` index from the
SARIF driver's rule list and folds the OWASP-/CWE-prefixed tags onto each
finding's ``evidence.parsed_value`` under the ``owasp`` / ``cwe`` keys.

FND-01 discipline: this is ENRICHMENT ONLY. The SARIF→Finding parser
(:func:`adapters.sarif.parser.sarif_to_findings`) is the single source of the
finding SET; :func:`annotate_owasp` never adds, drops, or reorders a finding —
it only attaches tag metadata. The returned list has the SAME length and order
as the input. A finding whose rule has no tags gets empty lists (never absent
keys), so downstream consumers can read ``parsed_value["owasp"]`` unconditionally.

OWASP tags may span editions (2017/2021/2025) — we keep whatever the rule
carries verbatim, prefix-filtered, without normalizing the edition.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Finding


def _index_rule_tags(sarif: dict[str, Any]) -> dict[str, list[str]]:
    """Build a ``{rule_id: tags}`` index from ``runs[].tool.driver.rules[]``.

    Reads ``rule["properties"]["tags"]`` for every rule with an ``id``. A rule
    with no tags maps to an empty list. Later runs/rules with the same id win
    (last-seen) — SARIF documents normally carry one driver, so this is moot in
    practice and only keeps the index total.
    """
    index: dict[str, list[str]] = {}
    for run in sarif.get("runs") or []:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            if not rule_id:
                continue
            props = rule.get("properties") or {}
            tags = props.get("tags") or []
            index[rule_id] = [t for t in tags if isinstance(t, str)]
    return index


def _split_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Partition tags into (owasp, cwe) by their well-known prefixes.

    OWASP tags start ``OWASP-`` (e.g. ``OWASP-A03:2021 - Injection``); CWE tags
    start ``CWE-`` (e.g. ``CWE-78: ...``). Any other tag (``security``, ...) is
    ignored. Order within each list mirrors the rule's tag order.
    """
    owasp = [t for t in tags if t.startswith("OWASP-")]
    cwe = [t for t in tags if t.startswith("CWE-")]
    return owasp, cwe


def annotate_owasp(findings: list[Finding], sarif: dict[str, Any]) -> list[Finding]:
    """Fold OWASP/CWE tags onto each finding's parsed_value, count-invariantly.

    For each finding, look up its rule (``parsed_value["rule_id"]``, falling back
    to ``Finding.rule_id``) in the SARIF driver's rule index, extract the
    OWASP-/CWE-prefixed tags, and write ``parsed_value["owasp"]`` +
    ``parsed_value["cwe"]`` (empty lists when the rule has no tags). Mutation is
    in place on the existing Finding objects — the finding COUNT and ORDER are
    unchanged (FND-01 enrichment, not a finding source).

    Args:
        findings: the findings produced by :func:`sarif_to_findings`.
        sarif: the SAME parsed SARIF document the findings were parsed from
            (its ``runs[].tool.driver.rules[]`` carries the tags).

    Returns:
        The same list (same length, same order), with each finding's
        ``evidence.parsed_value`` enriched with ``owasp`` + ``cwe`` lists.
    """
    rule_tags = _index_rule_tags(sarif)
    for finding in findings:
        rule_id = finding.evidence.parsed_value.get("rule_id") or finding.rule_id
        tags = rule_tags.get(rule_id, [])
        owasp, cwe = _split_tags(tags)
        finding.evidence.parsed_value["owasp"] = owasp
        finding.evidence.parsed_value["cwe"] = cwe
    return findings


__all__ = ["annotate_owasp"]
