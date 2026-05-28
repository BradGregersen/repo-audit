"""AdapterResult + InvocationResult contracts (Phase 3, D-22 mirror + D-39 input).

AdapterResult mirrors ``CollectorResult`` from Phase 2 (D-22) field-for-field
and adds two adapter-specific fields:

    * ``source_adapter`` — the registered adapter name (e.g. ``typescript-node``).
    * ``source_tool``    — the individual tool inside that adapter the result
                           came from (``tsc``, ``eslint``, ``knip``,
                           ``coverage_lcov``).

This pair is the load-bearing analogue of ``source_collector`` on
``CollectorResult``: every Phase-3 adapter result can be traced back to both
its adapter (which stack) and its underlying tool (which scanner).

InvocationResult is the D-39 input contract: the structured envelope every
parser receives. Parsers MUST consume ``InvocationResult`` rather than raw
``subprocess.CompletedProcess`` so they can be unit-tested against recorded
fixtures without invoking a live binary.

Failure semantics (D-25 mirror):
    Adapters NEVER raise across the orchestrator boundary. Internal
    try/except wrappers convert exceptions to AdapterResult(
        status='unavailable' | 'timeout', notes=<reason>, source_adapter=<name>
    ). The orchestrator's own try/except in ``run_adapters`` is a backstop.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repo_audit.schema.finding import Finding
from repo_audit.walker.skip_dirs import SkipReason

# Mirrors CollectorStatus from Phase 2 verbatim. Same Literal so adapter
# results and collector results route through the scope-ledger code path
# without type juggling.
AdapterStatus = Literal["ok", "unavailable", "timeout", "partial"]


class AdapterResult(BaseModel):
    """Per-tool result from a stack adapter (D-22 mirror).

    Mirrors ``CollectorResult`` field-for-field, then adds
    ``source_adapter`` + ``source_tool`` so a single result identifies both
    the stack (adapter) and the underlying tool (tsc/eslint/knip/...).

    ``extra='forbid'`` (D-03) means any typo at construction raises
    ``ValidationError`` before the object exists; this is the structural
    guard the SCH-08 family of contracts relies on.
    """

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    scanned_paths: list[str] = Field(default_factory=list)
    skipped: list[tuple[str, SkipReason]] = Field(default_factory=list)
    status: AdapterStatus = "ok"
    notes: str = ""
    source_adapter: str = ""
    source_tool: str = ""
    dimension: str = ""
    duration_ms: float = 0.0


class InvocationResult(BaseModel):
    """D-39 parser-input contract.

    Every tool parser consumes one ``InvocationResult`` per invocation,
    NEVER a raw ``subprocess.CompletedProcess``. This is the structural
    seam that lets parser unit tests feed recorded fixtures (the
    ``recorded_tool_output`` fixture in ``tests/adapters/conftest.py``
    returns ``(stdout, stderr, returncode)`` — the three fields below)
    without ever invoking a live binary.

    ``command`` and ``duration_ms`` are diagnostic; parsers MUST NOT
    depend on them for semantic decisions.
    """

    model_config = ConfigDict(extra="forbid")

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    command: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
