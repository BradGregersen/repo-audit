"""Top-level scan report and metadata.

schema_version is typed as Literal["1"] (D-21) so any future bump becomes
a deliberate code change that breaks at construction-time everywhere old
"1" is still hardcoded. Catches "we forgot to bump" at type-check time.

Phase 5's fleet aggregator reads each prior sidecar with a versioned reader;
additive changes don't bump the version, but renames/removals/retypes do.
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.detection import StackProfile
from repo_audit.schema.finding import Finding
from repo_audit.schema.scope_ledger import ScopeLedger


class ReportMeta(BaseModel):
    """Per-scan metadata (D-12).

    commit_sha is REPORT-LEVEL (D-04), not per-finding — the scan is a
    single snapshot of one commit; per-finding SHA is redundant noise.
    Per-finding git-blame enrichment is explicitly deferred to Phase 5+.
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    repo_slug: str = Field(..., min_length=1)         # D-16 derivation
    commit_sha: str                                    # D-04 / D-12; "UNCOMMITTED" allowed for fresh repos
    scan_date: date                                    # ISO-8601 on JSON dump
    tool_version: str                                  # D-12; from importlib.metadata
    detected_stacks: list[StackProfile] = Field(default_factory=list)  # D-12
    baseline_run: bool = True                          # D-12; always True in Phase 1
    partial: bool = False                              # D-31 banner trigger; Phase 1 default False


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
