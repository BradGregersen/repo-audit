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

from repo_audit.synthesis.config import SynthesisConfig, read_synthesis_config
from repo_audit.synthesis.factors import (
    blast_radius,
    exploitability,
    locus_class,
)
from repo_audit.synthesis.kev import (
    KEV_SET,
    is_kev,
    load_kev_set,
    refresh_kev_snapshot,
)
from repo_audit.synthesis.rank import rank_findings
from repo_audit.synthesis.record import PriorityScore
from repo_audit.synthesis.score import compute_priority_score, score_findings
from repo_audit.synthesis.select import select_top_findings, select_top_n
from repo_audit.synthesis.stage import run_synthesis

__all__ = [
    "PriorityScore",
    "SynthesisConfig",
    "read_synthesis_config",
    "blast_radius",
    "exploitability",
    "locus_class",
    "compute_priority_score",
    "score_findings",
    "rank_findings",
    "KEV_SET",
    "is_kev",
    "load_kev_set",
    "refresh_kev_snapshot",
    "select_top_findings",
    "select_top_n",
    "run_synthesis",
]
