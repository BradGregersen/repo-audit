"""Phase 17 verification layer — the "real not random" spine.

This package drives findings up the deterministic ``candidate → corroborated``
rung (``corroborate``), records an auditable corroboration/refutation trail in a
sidecar that keeps ``Finding`` ``extra='forbid'`` untouched (``record``), and
produces a downgrade-safe deterministic reachability signal (``reachability``).

Re-exports the stable public surface so callers import from the package root.
"""
from __future__ import annotations

from repo_audit.verification.record import (
    Citation,
    RefutationRecord,
    VerificationRecord,
    build_finding_ref,
)
from repo_audit.verification.stage import run_verification

__all__ = [
    "Citation",
    "RefutationRecord",
    "VerificationRecord",
    "build_finding_ref",
    "run_verification",
]
