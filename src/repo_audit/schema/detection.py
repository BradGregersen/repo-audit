"""Stack-detection result schema (D-20).

DetectionResult is a flat list of StackProfile records. Multi-stack repos
return multiple records. Tree/parent-child relationships between stacks are
handled at the adapter layer in Phase 3+, not by the detector.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class StackProfile(BaseModel):
    """A single detected stack with its root directory and matched manifests."""

    model_config = ConfigDict(extra="forbid")  # D-03

    stack: str = Field(..., min_length=1)
    root_dir: Path
    manifests: list[Path] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class DetectionResult(BaseModel):
    """The full set of stacks detected in a repo.

    Empty `stacks` list is a meaningful result per DETECT-03 (universal
    collectors still run in Phase 2+).
    """

    model_config = ConfigDict(extra="forbid")  # D-03

    stacks: list[StackProfile] = Field(default_factory=list)
