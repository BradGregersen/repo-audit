"""Pydantic schema contracts for repo-audit."""
from typing import TYPE_CHECKING, Any

from repo_audit.schema.enums import (
    Confidence,
    Dimension,
    EvidenceType,
    Severity,
)
from repo_audit.schema.finding import OUTPUT_SNIPPET_CAP, Evidence, Finding
from repo_audit.schema.detection import DetectionResult, StackProfile
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.schema.scope_ledger import (
    ScannedEntry,
    ScopeLedger,
    SkippedEntry,
    UnavailableEntry,
)

# Agent boundary types (D-54, D-64) are re-exported LAZILY via PEP 562
# __getattr__ to break a re-export import cycle: agent.schema imports
# schema.enums (which runs this package __init__), and a direct
# `from repo_audit.schema.agent_report import ...` here would re-enter
# the still-initializing agent.schema module when agent.schema is the import
# entry point. Lazy resolution defers the agent.schema import to first
# attribute access, by which point both packages are fully initialized.
# Class identity is preserved (same object as repo_audit.agent.schema).
if TYPE_CHECKING:  # pragma: no cover - import-time typing aid only
    from repo_audit.schema.agent_report import (
        AgentScanReport,
        DimensionNarrative,
        FaithfulnessViolation,
        SeverityCall,
    )

_AGENT_REEXPORTS = frozenset(
    {"AgentScanReport", "DimensionNarrative", "SeverityCall", "FaithfulnessViolation"}
)


def __getattr__(name: str) -> Any:
    """PEP 562 lazy re-export of the agent boundary types."""
    if name in _AGENT_REEXPORTS:
        from repo_audit.schema import agent_report

        return getattr(agent_report, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Dimension", "Severity", "EvidenceType", "Confidence",
    "Evidence", "Finding", "OUTPUT_SNIPPET_CAP",
    "StackProfile", "DetectionResult",
    "ReportMeta", "ScanReport",
    "AgentScanReport", "DimensionNarrative", "SeverityCall", "FaithfulnessViolation",
    "ScopeLedger", "ScannedEntry", "SkippedEntry", "UnavailableEntry",
]
