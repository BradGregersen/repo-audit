"""Finding and Evidence models — the contract every Phase 2+ collector binds to.

SCH-08 (no raw secret value) is enforced by TWO mechanisms together:
    (a) Field absence — there is no `value`, `secret`, `match`, `raw`, or
        any similar field on Finding or Evidence.
    (b) ConfigDict(extra='forbid') — construction or JSON deserialization
        with such a key raises ValidationError before the object exists.

DO NOT ADD a field named value/secret/match/raw/original/text/string/literal.
A unit test (test_finding_forbids_secret_value_field) asserts these names are
absent from Finding.model_fields; that test MUST stay green.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from repo_audit.schema.enums import (
    Confidence,
    Dimension,
    EvidenceType,
    Severity,
)

# D-02: output_snippet cap. 2048 chars protects agent context (Phase 4) and
# prevents log explosion from noisy collectors (gradle stack traces, tsc errors).
OUTPUT_SNIPPET_CAP: int = 2048
_TRUNCATION_MARKER_TEMPLATE: str = "… [+{n} chars truncated]"


class Evidence(BaseModel):
    """Structured evidence body (D-01).

    NEVER contains a raw secret value. SCH-08 is enforced via:
    - no `value` / `secret` / `match` / `raw` field declared here
    - extra='forbid' rejects any such kwarg at construction time
    - the `output_snippet` field's cap (D-02) discourages dumping raw tool
      output verbatim; collectors should redact before construction
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    tool: str = Field(..., min_length=1)
    output_snippet: str = ""
    parsed_value: dict[str, Any] = Field(default_factory=dict)
    line_range: tuple[int, int] | None = None

    @field_validator("output_snippet", mode="after")
    @classmethod
    def _cap_output_snippet(cls, v: str) -> str:
        """D-02: truncate at 2048 chars; append literal marker '… [+N chars truncated]'."""
        if len(v) <= OUTPUT_SNIPPET_CAP:
            return v
        overflow = len(v) - OUTPUT_SNIPPET_CAP
        return v[:OUTPUT_SNIPPET_CAP] + _TRUNCATION_MARKER_TEMPLATE.format(n=overflow)


class Finding(BaseModel):
    """Single audit finding.

    SCH-08 — type-level prohibition of raw secret values:
        There is NO field named `value`, `secret`, `match`, `raw`, `original`,
        or anything else that could carry a raw secret value. Combined with
        extra='forbid', any attempt to construct Finding(value="...") raises
        ValidationError before the object exists. This is STRUCTURAL prohibition,
        not a runtime check.

    SAFE-01 (D-17) — critical+static requires a confidence_caveat (enforced below).
    SAFE-03 (D-19) — presence_only findings must have severity='info' (enforced below).

    Validator decorator declaration order is not load-bearing —
    _enforce_critical_static_caveat and _enforce_presence_only_severity_ceiling
    raise on independent invariants. Future additions should preserve
    independence rather than relying on ordering.
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    dimension: Dimension                       # SCH-02
    severity: Severity                          # SCH-05
    file: str | None = None
    line: int | None = None
    evidence: Evidence                          # D-01
    evidence_type: EvidenceType                 # SCH-03
    confidence: Confidence                      # SCH-04
    recommendation: str = ""
    source_tool: str = ""
    source_collector: str = ""
    rule_id: str = ""
    confidence_caveat: str | None = None        # D-17

    @model_validator(mode="after")
    def _enforce_critical_static_caveat(self) -> "Finding":
        """SAFE-01 / D-17: critical+static requires non-empty confidence_caveat."""
        if (
            self.severity == "critical"
            and self.evidence_type == "static"
            and (self.confidence_caveat is None or not self.confidence_caveat.strip())
        ):
            raise ValueError(
                "SAFE-01: severity='critical' with evidence_type='static' requires a "
                "non-empty confidence_caveat — runtime was not verified."
            )
        return self

    @model_validator(mode="after")
    def _enforce_presence_only_severity_ceiling(self) -> "Finding":
        """SAFE-03 / D-19: parsed_value.presence_only=True requires severity='info'.

        CONTEXT.md D-19: 'severity no higher than info' AND forbids {critical, blocker, major}.
        Strictest reading: severity == 'info' only. Encoded here.
        """
        if self.evidence.parsed_value.get("presence_only") is True and self.severity != "info":
            raise ValueError(
                f"SAFE-03: parsed_value.presence_only=True requires severity='info'; "
                f"got severity={self.severity!r}. Presence-only findings cannot promote "
                f"without an additional semantic-check signal."
            )
        return self
