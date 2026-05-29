"""D-39 knip parser: knip 6.x JSON → Finding.

Verified knip 6.14.2 JSON shape (RESEARCH §"Code Examples"):

    {"issues": [{"file": "<path>", "owners": [], "binaries": [],
                 "catalog": [], "dependencies": [{"name": ..., "line": ...,
                 "col": ..., "pos": ...}], "devDependencies": [...],
                 "duplicates": [...], "enumMembers": [...],
                 "exports": [...], "files": [{"name": ...}],
                 "namespaceMembers": [...], "optionalPeerDependencies": [...],
                 "types": [...], "unlisted": [...], "unresolved": [...]}]}

Per D-50 + SAFE-05: EVERY knip Finding ships at
    confidence='candidate', severity='info', dimension='architecture_rot'.

Per Decision B / D-51', SCH-04 widened permits major/minor/info at
candidate (only critical/blocker are rejected). The knip-specific D-50
cap is therefore enforced by the parser's ``_KNIP_SEVERITY = 'info'``
CONSTANT — changing it to 'major' would NOT trip SCH-04 but WOULD trip
the parser-internal test. Constant is named so the change is visible in
code review diff.

Recommendation text says 'verify' — SAFE-05's "≥N methods before
condemning" discipline encoded in code (the forbidden word is captured
as a test, not in this docstring, so the test can pin its absence
structurally).

Per RESEARCH Pitfall 7: knip in JSON mode exits 0 regardless of issues.
The adapter calls this parser whenever it has stdout (status='ok'); the
parser tolerates both clean and issues cases.

Malformed JSON → returns [] (no raise).
"""
from __future__ import annotations

import json
from typing import Any

from repo_audit.adapters.base import InvocationResult
from repo_audit.schema.finding import Evidence, Finding

# D-50: locked invariants — change only with a paired SCH-04 / SAFE-05 update.
_KNIP_SEVERITY: str = "info"
_KNIP_CONFIDENCE: str = "candidate"
_KNIP_DIMENSION: str = "architecture_rot"

# SAFE-05 recommendation phrasing — encourages verification, never the
# strong-action word that the test pins as absent.
_CANDIDATE_RECOMMENDATION: str = (
    "Candidate dead code per knip — verify with grep across the workspace "
    "and any dynamic-import call sites before removing."
)

# Category → rule_id label (RESEARCH _CATEGORY_LABELS, normalised to
# snake_case). Each per-issue category produces ONE Finding per item.
_CATEGORY_LABELS: dict[str, str] = {
    "files": "unused_file",
    "exports": "unused_export",
    "types": "unused_type",
    "dependencies": "unused_dependency",
    "devDependencies": "unused_devDependency",
    "duplicates": "duplicate_export",
    "enumMembers": "unused_enum_member",
    "unlisted": "unlisted_dependency",
    "unresolved": "unresolved_import",
    "namespaceMembers": "unused_namespace_member",
}


def parse(inv: InvocationResult) -> list[Finding]:
    """Transform knip JSON output into Findings (one per item per category)."""
    try:
        data = json.loads(inv.stdout or "{}")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    for issue in data.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        file_path = issue.get("file", "")
        for category, label in _CATEGORY_LABELS.items():
            items = issue.get(category) or []
            if not isinstance(items, list):
                continue
            for item in items:
                finding = _make_finding(file_path, category, label, item)
                if finding is not None:
                    findings.append(finding)
    return findings


def _make_finding(
    file_path: str,
    category: str,
    label: str,
    item: Any,
) -> Finding | None:
    """Construct a single knip Finding. Returns None if item shape is unparseable."""
    if isinstance(item, dict):
        symbol = item.get("name", "")
        line = item.get("line")
        col = item.get("col")
    elif isinstance(item, str):
        symbol = item
        line = None
        col = None
    else:
        return None
    line_int = (
        int(line) if isinstance(line, int) and not isinstance(line, bool) else None
    )
    col_int = (
        int(col) if isinstance(col, int) and not isinstance(col, bool) else None
    )
    return Finding(
        dimension=_KNIP_DIMENSION,                  # D-48
        severity=_KNIP_SEVERITY,                    # D-50 parser-cap
        confidence=_KNIP_CONFIDENCE,                # D-50
        evidence_type="static",                     # D-17
        file=file_path,
        line=line_int,
        source_tool="knip",
        source_collector="typescript_adapter",
        rule_id=label,                              # e.g., "unused_export"
        recommendation=_CANDIDATE_RECOMMENDATION,   # SAFE-05
        evidence=Evidence(
            tool="knip",
            output_snippet=f"{label}: {symbol} ({file_path}:{line_int or '?'})",
            parsed_value={
                "symbol_name": symbol,
                "file": file_path,
                "line": line_int,
                "col": col_int,
                "knip_category": category,
            },
            line_range=(line_int, line_int) if line_int else None,
        ),
    )


__all__ = [
    "_CATEGORY_LABELS",
    "_KNIP_CONFIDENCE",
    "_KNIP_DIMENSION",
    "_KNIP_SEVERITY",
    "parse",
]
