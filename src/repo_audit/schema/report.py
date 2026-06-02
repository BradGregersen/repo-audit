"""Top-level scan report and metadata.

schema_version is typed as Literal["1"] (D-21) so any future bump becomes
a deliberate code change that breaks at construction-time everywhere old
"1" is still hardcoded. Catches "we forgot to bump" at type-check time.

Phase 5's fleet aggregator reads each prior sidecar with a versioned reader;
additive changes don't bump the version, but renames/removals/retypes do.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.detection import StackProfile
from repo_audit.schema.enums import AgentStatus
from repo_audit.schema.finding import Finding
from repo_audit.schema.scope_ledger import ScopeLedger

# FaithfulnessViolation lives in agent.schema (D-64 canonical home). A
# top-level eager import here creates a cycle ONLY when the agent package
# is the import entry point (e.g. `import repo_audit.agent.options`
# before any schema import): agent/__init__ -> agent.schema ->
# schema.enums -> schema/__init__ -> schema.report -> agent.schema (partial).
# Plan 04-03 imported it eagerly assuming schema is always imported first;
# Plan 04-04 surfaced the latent cycle via importorskip on an agent
# submodule. The fix is a TYPE_CHECKING-only import + a deferred
# model_rebuild() at module bottom, so the annotation is a string forward
# ref that Pydantic resolves once both packages are fully initialized.
if TYPE_CHECKING:  # pragma: no cover - typing aid only
    from repo_audit.agent.schema import FaithfulnessViolation


class FeedProvenance(BaseModel):
    """Per-source vuln-feed reproducibility stamp (FND-02 / D-07-02).

    One entry per scanner (osv-scanner, grype). queried_at is
    reproducibility METADATA and lives here, NEVER on a Finding
    (RESEARCH Pitfall 7 — a queried_at leaking onto a finding breaks
    SC-5 bit-identical re-runs). advisory_count is Optional: ship None
    rather than invent a number when a tool does not report it
    (carried constraint — deterministic collectors own all numbers).
    """

    model_config = ConfigDict(extra="forbid")
    feed: str
    scanner: str
    scanner_version: str
    db_snapshot_date: date | None = None
    queried_at: datetime
    advisory_count: int | None = None


class ReportMeta(BaseModel):
    """Per-scan metadata (D-12).

    commit_sha is REPORT-LEVEL (D-04), not per-finding — the scan is a
    single snapshot of one commit; per-finding SHA is redundant noise.
    Per-finding git-blame enrichment is explicitly deferred to Phase 5+.

    Phase 4 additive extension (D-65, D-67, D-69, D-70): 7 Optional fields
    populated by the agent loop / faithfulness gate / corroboration check /
    exec-summary curation. schema_version stays "1" per D-21 (Phase 5 fleet
    aggregator reads forward-compatibly). All new fields default to None or
    an empty list so existing Phase 1-3 JSON sidecars round-trip-validate.
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    repo_slug: str = Field(..., min_length=1)         # D-16 derivation
    commit_sha: str                                    # D-04 / D-12; "UNCOMMITTED" allowed for fresh repos
    scan_date: date                                    # ISO-8601 on JSON dump
    tool_version: str                                  # D-12; from importlib.metadata
    detected_stacks: list[StackProfile] = Field(default_factory=list)  # D-12
    baseline_run: bool = True                          # D-12; always True in Phase 1
    partial: bool = False                              # D-31 banner trigger; Phase 1 default False

    # --- Phase 4 agent-loop fields (D-65, D-67, D-69, D-70) — all Optional. ---
    # `schema_version` stays "1" (D-21): additive Optional fields are
    # forward-compatible. Phase 5 fleet aggregator reads the existing 7
    # fields and gracefully ignores any it does not know.

    # D-67 — populated by Plan 04-06's session loop per the exception →
    # status mapping. 'ok' is the success path; the 4 'unavailable_*'
    # states and 'cost_capped' all render via the D-09 pending-marker
    # pattern in Plan 04-08. None means the agent step has not run yet
    # (e.g., --no-agent CLI flag set in Plan 04-09).
    agent_status: AgentStatus | None = None

    # D-65 — populated from ResultMessage.total_cost_usd at loop completion
    # (or 0.0 / None when disconnected pre-result-message). Under Max OAuth
    # auth this is an ESTIMATED EQUIVALENT, not an enforced billing cap;
    # under API-key auth it is an actual figure. Footer text in Plan 04-08
    # disambiguates.
    total_cost_usd: float | None = None

    # D-65 — running tally of AssistantMessage.usage['input_tokens'] +
    # AssistantMessage.usage['output_tokens'], summed across all turns.
    # ALWAYS populated when agent_status != None (including 'cost_capped').
    # This is the ENFORCEABLE cap under Max OAuth.
    token_usage: int | None = None

    # D-65 / SC-5 — overall repo-audit scan duration (collector + adapter + agent
    # + render phases combined). Always populated when an agent step ran.
    # See RESEARCH Open Question 2 — overall vs agent-only breakdown is
    # planner discretion; Phase 4 ships overall duration.
    wall_clock_seconds: float | None = None

    # D-64 / AGENT-08 — populated by Plan 04-07's check_faithfulness pass.
    # One entry per sentence stripped by the gate. Plan 04-08 renders a
    # count-only footer line; the JSON sidecar carries the full record
    # for audit. Default factory keeps Phase 1-3 JSON sidecars valid
    # (the field appears as [] not missing).
    faithfulness_violations: list[FaithfulnessViolation] = Field(
        default_factory=list,
    )

    # D-70 / SAFE-07 — populated by Plan 04-08's render-time dilution-strip
    # pass over agent_output.executive_summary. Each entry is the
    # original sentence that mentioned major/minor/info counts and was
    # stripped from the rendered exec summary. Deterministic header
    # (built from the structurally-counted finding store) is pre-pended
    # regardless.
    exec_summary_dilution_strips: list[str] = Field(default_factory=list)

    # D-69 / SAFE-06 — populated by Plan 04-08's render-time corroboration
    # check. Each entry records a SeverityCall whose
    # agent-claimed corroborated_by disagreed with the deterministic
    # is_corroborated(finding, all_findings) check. JSON-sidecar audit
    # log only; never alters the rendered output (the deterministic check
    # is authoritative per D-69).
    agent_corroboration_disputes: list[dict[str, object]] = Field(
        default_factory=list,
    )

    # D-051-02 / SECRET-LINT-SPLIT-01 — populated by the render-local
    # entropy redact-and-continue path (render/secret_lint.lint_and_redact_entropy,
    # wired at renderer.py's lint sites). Each entry records ONE entropy-backstop
    # token that was redacted in place to ``[REDACTED:N]`` so a legitimate report
    # could still be written instead of hard-refusing on a benign high-entropy
    # token (lockfile hashes, minified strings). The high-confidence layers
    # (gitleaks + known-patterns) still HARD-block (raise SecretsDetected → exit 2);
    # only ``rule_id == "entropy-backstop"`` hits route here.
    #
    # VALUE-BLIND: each entry mirrors SecretHit's exposed fields exactly —
    # ``{"line": int, "rule_id": "entropy-backstop", "redacted_len": int}``. The
    # raw redacted token is NEVER stored (D-051-02 / T-051-07). schema_version
    # stays "1" (D-21): additive Optional list, forward-compatible with the
    # Phase 5 fleet aggregator.
    entropy_redactions: list[dict[str, object]] = Field(default_factory=list)

    # FND-02 / D-07-02 — per-source vuln-feed reproducibility stamp. One
    # entry per scanner (osv, grype). Additive Optional list; schema_version
    # stays "1" (D-21), forward-compatible with the Phase 5 fleet aggregator.
    # Default empty list so Phase 1-6 sidecars (which have no feed_provenance
    # key) still round-trip-validate.
    feed_provenance: list[FeedProvenance] = Field(default_factory=list)


class ScanReport(BaseModel):
    """The structured scan report. Serialized as the JSON sidecar (SCH-06).

    Phase 1: findings is always empty (no collectors yet). The renderer
    produces a 7-dimension boilerplate with pending markers per D-09/10/11.
    Phase 2+: collectors populate findings; the same schema serializes.
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    # SCH-07 / D-21: literal "1" — typed bumps catch "forgot to update" at construction.
    schema_version: Literal["1"] = "1"
    meta: ReportMeta
    findings: list[Finding] = Field(default_factory=list)
    scope_ledger: ScopeLedger = Field(default_factory=ScopeLedger)  # D-30


# Resolve the `list[FaithfulnessViolation]` forward reference on ReportMeta.
# By the time this module finishes executing, agent.schema is importable:
# - schema-first entry: agent.schema fully loads here on demand.
# - agent-first entry: this runs while agent.schema is still partial, so the
#   eager rebuild would fail; we defer it to first ReportMeta construction
#   via a one-shot guard instead of forcing it at import time.
def _rebuild_report_meta() -> None:
    """Resolve agent.schema forward refs once both packages are initialized."""
    from repo_audit.agent.schema import (  # noqa: F401 — namespace for rebuild
        FaithfulnessViolation,
    )

    ReportMeta.model_rebuild(
        _types_namespace={"FaithfulnessViolation": FaithfulnessViolation}
    )


try:
    _rebuild_report_meta()
except ImportError:
    # agent.schema is mid-initialization (agent package was the import
    # entry point). The rebuild will be retriggered lazily — see the
    # __init_subclass__-free fallback: schema/__init__ completes, then the
    # agent package finishes and any first ReportMeta(...) construction
    # triggers Pydantic's own lazy ref resolution. To be safe we also
    # rebuild from agent.schema's module tail (see agent/schema.py).
    pass
