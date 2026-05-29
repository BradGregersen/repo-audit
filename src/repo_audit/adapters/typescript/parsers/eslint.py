"""ESLint --format=json findings (TypeScript stack adapter).

When to use: when narrating the `quality` dimension for code style /
anti-patterns / complexity. Also surfaces some `security` findings when
rule_id starts with `security/` or `no-secrets/` (the adapter.yaml
rule_overrides bump these to severity=critical with confidence_caveat).
Each Finding's `evidence.parsed_value` carries the ESLint message.

When NOT to use: for type errors (use get_tsc_diagnostics), for dead
code (use get_knip_dead_code), or for coverage (use get_lcov_coverage).
"""
# Implementation notes (preserved from the original module docstring):
# D-39 eslint parser: eslint 9.x JSON -> Finding.
# Verified eslint 9.39.3 JSON shape (RESEARCH §"Code Examples"):
#   [{"filePath": "...", "messages": [{"ruleId": ..., "severity": ...,
#     "message": ..., "line": ..., "column": ..., ...}], ...}]
# Routing precedence (D-49): (1) CONFIG.rule_overrides[ruleId] literal
#   dict lookup wins on conflict; (2) CONFIG.rule_override_globs fnmatch in
#   declaration order, first match wins; (3) default dimension='quality',
#   severity from eslint int (2 -> 'major', 1 -> 'minor').
# SCH-03 invariant: any override that raises severity to 'critical' AND
#   evidence_type='static' MUST supply confidence_caveat. The YAML provides
#   caveats for the current overrides; the parser supplies a fallback for
#   any user-overlay (Phase 7) that omits it.
# Malformed input -> returns [] (no raise). The adapter layer sets
#   status='unavailable' at the boundary when the JSON parse fails and the
#   parser hands back an empty list.
# Checker Warning 11 + Warning 13: the rule_overrides + glob tables are
#   resolved at CALL time (not module-load) and imported lazily inside the
#   resolver helper — so Phase 7's user-overlay loader can update CONFIG
#   between adapter package import and parser invocation without a parser
#   reload, and so the parser module does not constrain import ordering
#   with the adapter package itself.
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import Any

from repo_audit.adapters.base import InvocationResult
from repo_audit.schema.finding import Evidence, Finding

# SCH-03 fallback caveat — used when a rule override promotes a finding
# to ``critical`` without a YAML-supplied caveat (defensive against the
# Phase 7 user-overlay path).
_FALLBACK_CRITICAL_CAVEAT: str = (
    "Static analysis match; runtime not verified."
)


def _current_overrides() -> tuple[dict, list]:
    """Resolve ``(rule_overrides_literal, rule_override_globs)`` from CONFIG.

    Called on every ``parse()`` invocation; ensures Phase 7's user-overlay
    loader (which may mutate CONFIG between adapter package import and
    parser call) is honored without a parser reload.

    Per Warning 13: the CONFIG import is done lazily INSIDE this helper
    so import-order between adapter package init and parser module does
    not constrain ordering. By the time a parser runs, the adapter
    package has already been imported (``adapter.run()`` is the dispatch
    site).
    """
    from repo_audit.adapters.typescript import (  # noqa: WPS433
        CONFIG as _CFG,
    )

    eslint_cfg = _CFG.get("tools", {}).get("eslint", {})
    return (
        eslint_cfg.get("rule_overrides") or {},
        eslint_cfg.get("rule_override_globs") or [],
    )


def _route(rule_id: str, severity_int: int) -> tuple[str, str, str | None]:
    """Apply D-49 override precedence.

    Returns ``(dimension, severity_str, caveat_or_None)``.

    Args:
        rule_id: eslint rule ID, possibly ``""`` for built-in syntax errors.
        severity_int: 1 (warning) or 2 (error).
    """
    # Resolve overrides at CALL TIME (Warning 11) — do not close over
    # module-level constants, so Phase 7 user-overlay edits flow through.
    literal_overrides, glob_overrides = _current_overrides()
    # Step 1 — literal override (highest precedence).
    if rule_id and rule_id in literal_overrides:
        ov = literal_overrides[rule_id]
        return ov["dimension"], ov["severity"], ov.get("confidence_caveat")
    # Step 2 — glob override.
    if rule_id:
        for ov in glob_overrides:
            if fnmatchcase(rule_id, ov["pattern"]):
                return (
                    ov["dimension"],
                    ov["severity"],
                    ov.get("confidence_caveat"),
                )
    # Step 3 — default (D-48 + D-51 mapping).
    sev_str = "major" if severity_int == 2 else "minor"
    return "quality", sev_str, None


def parse(inv: InvocationResult) -> list[Finding]:
    """Transform eslint JSON output into Findings.

    Adapter contract: invoked when ``status='ok'``. Tolerates malformed
    JSON by returning ``[]`` (the adapter then flips status to
    ``'unavailable'`` based on stdout JSON parse failure at the boundary).
    """
    try:
        per_file: list[Any] = json.loads(inv.stdout or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(per_file, list):
        return []
    findings: list[Finding] = []
    for entry in per_file:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("filePath", "")
        for msg in entry.get("messages") or []:
            if not isinstance(msg, dict):
                continue
            rule_id = msg.get("ruleId") or ""
            try:
                severity_int = int(msg.get("severity") or 0)
            except (TypeError, ValueError):
                continue
            if severity_int == 0:
                # Suppressed; defensive skip (shouldn't appear in messages[]).
                continue
            dimension, sev_str, caveat = _route(rule_id, severity_int)
            line_no = msg.get("line")
            line_int = (
                int(line_no)
                if isinstance(line_no, int) and not isinstance(line_no, bool)
                else None
            )
            column = msg.get("column")
            message_text = msg.get("message", "")
            kwargs: dict[str, Any] = dict(
                dimension=dimension,
                severity=sev_str,
                file=file_path,
                line=line_int,
                evidence_type="static",            # D-17
                confidence="high",
                recommendation=(
                    f"Resolve eslint {rule_id or '<syntax>'}: {message_text}"
                ),
                source_tool="eslint",
                source_collector="typescript_adapter",
                rule_id=rule_id,
                evidence=Evidence(
                    tool="eslint",
                    output_snippet=message_text,
                    parsed_value={
                        "rule_id": rule_id,
                        "column": column,
                        "severity_int": severity_int,
                    },
                    line_range=(line_int, line_int) if line_int else None,
                ),
            )
            # SCH-03: critical + static ⇒ mandatory caveat.
            if sev_str == "critical":
                kwargs["confidence_caveat"] = (
                    caveat or _FALLBACK_CRITICAL_CAVEAT
                )
            elif caveat:
                kwargs["confidence_caveat"] = caveat
            findings.append(Finding(**kwargs))
    return findings


__all__ = ["_FALLBACK_CRITICAL_CAVEAT", "parse"]
