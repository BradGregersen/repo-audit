"""Phase 18 synthesis / prioritization — the deterministic trust-tail spine.

Python owns every number (D-18-03 / D-69): the composite priority is a
value-derived multiplicative product (severity × confidence × exploitability ×
blast-radius), EPSS/KEV fuse as raise-only signals, and the ranking is
shuffle-stable (a shuffled finding input yields the IDENTICAL order — SYN-01).
The per-finding ``PriorityScore`` rides a SIDECAR keyed on ``candidate_token``
(the 17-04 landmine — never the non-unique ``build_finding_ref``).

Re-exports the stable public surface so callers import from the package root.
"""
from __future__ import annotations

from repo_audit.synthesis.factors import (
    blast_radius,
    exploitability,
    locus_class,
)
from repo_audit.synthesis.record import PriorityScore

__all__ = [
    "PriorityScore",
    "blast_radius",
    "exploitability",
    "locus_class",
]
