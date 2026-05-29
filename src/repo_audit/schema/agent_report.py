"""Re-export of agent.schema types under the schema/ package.

This shim exists so callers can write `from repo_audit.schema import
AgentScanReport` consistent with how they already write `from
repo_audit.schema import ScanReport, Finding, Evidence`. The
canonical home is `repo_audit.agent.schema` (Plan 04-02 Task 1)
because the boundary type semantically belongs to the agent package
(D-54 makes it the emit_report tool's input_schema). The schema/ shim
is for ergonomic imports only.

DO NOT redefine the models here. DO NOT add aliasing classes. This is
a flat re-export only.
"""
from repo_audit.agent.schema import (
    AgentScanReport,
    DimensionNarrative,
    FaithfulnessViolation,
    SeverityCall,
)

__all__ = [
    "AgentScanReport",
    "DimensionNarrative",
    "SeverityCall",
    "FaithfulnessViolation",
]
