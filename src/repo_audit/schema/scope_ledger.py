"""ScopeLedger (D-30) — three-subsection ledger for SAFE-04 + SAFE-08 honesty.

JSON shape (used by Phase 5 trend deltas):
    {
        "scanned": [{"dir": str, "file_count": int, "collectors": [str]}, ...],
        "skipped": [{"dir": str, "reason": SkipReason}, ...],
        "unavailable": [{"dimension": str, "collector": str, "reason": str}, ...],
        "notes": str
    }

The markdown rendering of these three subsections lands in Plan 02-06's
template extension; this module ONLY defines the schema contract.
"""
from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field

from repo_audit.walker.skip_dirs import SkipReason


class ScannedEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dir: str
    file_count: int
    collectors: list[str] = Field(default_factory=list)


class SkippedEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dir: str
    reason: SkipReason


class UnavailableEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str
    collector: str
    reason: str


class ScopeLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanned: list[ScannedEntry] = Field(default_factory=list)
    skipped: list[SkippedEntry] = Field(default_factory=list)
    unavailable: list[UnavailableEntry] = Field(default_factory=list)
    notes: str = ""
