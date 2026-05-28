"""CollectorResult contract (D-22) — every Phase 2 collector returns this shape.

Failure semantics (D-25):
    Collectors NEVER raise across the orchestrator boundary. Internal
    try/except wrappers convert exceptions to CollectorResult(
        status='unavailable' | 'timeout', notes=<reason>, source_collector=<name>
    ). The orchestrator's own try/except is a backstop.

Self-reporting (D-30):
    scanned_paths + skipped + status feed the ScopeLedger directly; no
    separate ledger-population pass.
"""
from __future__ import annotations
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.finding import Finding
from repo_audit.walker.skip_dirs import SkipReason

CollectorStatus = Literal["ok", "unavailable", "timeout", "partial"]


class CollectorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[Finding] = Field(default_factory=list)
    scanned_paths: list[str] = Field(default_factory=list)
    skipped: list[tuple[str, SkipReason]] = Field(default_factory=list)
    status: CollectorStatus = "ok"
    notes: str = ""
    source_collector: str = ""
    dimension: str = ""
    duration_ms: float = 0.0
