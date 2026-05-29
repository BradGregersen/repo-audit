"""Agent-emitted scan report Pydantic types (D-54, D-64).

These models define the structured boundary across which the Claude Agent
SDK emits its narrative payload. The single `emit_report(report: AgentScanReport)`
MCP tool (Plan 04-05) registers `input_schema=AgentScanReport.model_json_schema()`
and the SDK validates agent calls against the schema BEFORE invoking our
handler (D-54). Our handler then runs `AgentScanReport.model_validate(args)`
for defense-in-depth (D-55 triggers the repair loop on the second validation
failure path).

`extra='forbid'` on every model is D-03 carried forward from Phase 1:
any unexpected field at construction or JSON-deserialization raises
ValidationError before the object exists. The agent CANNOT smuggle a
`markdown` field past this boundary (AGENT-04 contract).

FaithfulnessViolation (D-64) is defined here — not in render/faithfulness.py
— because Plan 04-03's ReportMeta needs `list[FaithfulnessViolation]` and
keeping all agent-related Pydantic shapes in one module is the right
cohesion. Plan 04-07's gate produces instances; Plan 04-03's meta stores
them; this module owns the shape.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.enums import Dimension, Severity


class SeverityCall(BaseModel):
    """Agent's per-finding severity confirmation/uplift (D-54).

    finding_ref is a composite string the agent emits to reference one
    deterministic Finding: "{source_tool}::{rule_id}::{file}:{line}".
    The renderer matches it back against the structurally-counted
    Finding store; an unmatchable finding_ref is logged to
    meta.agent_corroboration_disputes[] but never alters the rendered
    output (D-69 — the deterministic check is authoritative).

    corroborated_by is the agent's claim about which other source_tools
    back this severity. Per D-69, this is ADVISORY ONLY — the
    render-time `is_corroborated(finding, all_findings)` check is the
    structural signal. Mismatch logs to meta but does not alter render.
    """

    model_config = ConfigDict(extra="forbid")
    finding_ref: str = Field(..., min_length=1)
    agent_severity: Severity
    corroborated_by: list[str] = Field(default_factory=list)


class DimensionNarrative(BaseModel):
    """Per-dimension narrative paragraph + severity calls (D-54).

    narrative is the prose subject to the D-64 faithfulness gate at
    render time. Every numeric token in this string must trace back to
    the pre-computed AllowedNumbers set (D-62) or be elided sentence-by-
    sentence (D-63). The gate runs after secret_lint (D-07) and
    completion_honesty_lint (D-32) at the SAME render chokepoint —
    the three together are the defense-in-depth trio against agent
    hallucination (RESEARCH §"Defense in depth on hallucinations").
    """

    model_config = ConfigDict(extra="forbid")
    dimension: Dimension
    narrative: str
    severity_calls: list[SeverityCall] = Field(default_factory=list)


class AgentScanReport(BaseModel):
    """The agent → renderer boundary type (D-54, AGENT-04).

    Registered as the input_schema of the `emit_report` MCP tool
    (Plan 04-05); the SDK validates incoming agent calls against this
    Pydantic-derived JSON Schema before passing args to our handler.
    Free-form final-message JSON and per-dimension emit_dim()
    accumulation are explicitly REJECTED alternatives per D-54.

    AGENT-04 contract: this type has NO field named `markdown`, `md`,
    `html`, or any other markdown-shaped string. The Jinja renderer
    composes the final markdown from the typed payload + the
    structurally-counted Finding store. The agent NEVER authors raw
    markdown — only typed prose paragraphs in narrative fields.

    SAFE-07 contract: executive_summary is subject to the D-70
    deterministic-header pre-pend + dilution-strip pass at render
    time. The agent may put context in this string ("the critical
    findings cluster in the auth module") but the authoritative
    count line ("**N blocker, M critical finding(s)** across K
    dimension(s)") is pre-pended by the renderer from the
    structurally-counted store. Sentences mentioning major/minor/info
    counts are stripped sentence-by-sentence.
    """

    model_config = ConfigDict(extra="forbid")
    dimensions: list[DimensionNarrative] = Field(default_factory=list)
    executive_summary: str = ""
    cross_cutting_notes: str | None = None


class FaithfulnessViolation(BaseModel):
    """One sentence stripped by the D-64 faithfulness gate.

    Recorded in three places per D-64:
      1. ScanReport.meta.faithfulness_violations[] — full record into
         JSON sidecar (Plan 04-03 adds this field to ReportMeta).
      2. Stderr at scan time — one line per violation, 80-char preview
         of original_sentence (rendered by Plan 04-07).
      3. Markdown footer — count line only, NEVER the content
         (could itself contain leaks; rendered by Plan 04-08).

    original_sentence MAY be secret-linted before being stored
    (planner discretion per D-64; defense-in-depth so a hallucinated
    secret value in agent prose does not survive into the audit log).
    Plan 04-07 applies the secret_lint pass.

    nearest_allowed is a debugging aid — the closest AllowedNumbers
    entry to the offending token (or None if the token did not parse
    as a float). Helps the planner triage false positives when the
    gate strips a sentence whose token was "close but not within 5%".
    """

    model_config = ConfigDict(extra="forbid")
    original_sentence: str
    offending_tokens: list[str] = Field(default_factory=list)
    dimension: Dimension | None = None
    paragraph_index: int = 0
    nearest_allowed: float | None = None


# Cycle resolution (Plan 04-04): when the AGENT package is the import entry
# point, schema.report loads while THIS module is still partial, so
# report.py's eager ReportMeta.model_rebuild() is skipped (ImportError
# branch). Now that FaithfulnessViolation is fully defined, re-run that
# rebuild so ReportMeta's `list[FaithfulnessViolation]` forward ref resolves.
# When the SCHEMA package is the entry point, report.py already rebuilt
# successfully and this is a cheap idempotent no-op.
def _resolve_report_meta_forward_refs() -> None:
    import sys

    report_mod = sys.modules.get("repo_audit.schema.report")
    if report_mod is not None:
        report_mod.ReportMeta.model_rebuild(
            _types_namespace={"FaithfulnessViolation": FaithfulnessViolation}
        )


_resolve_report_meta_forward_refs()
