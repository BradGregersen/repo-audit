"""Cross-stack supply-chain adapter package (Phase 12).

Like ``adapters/sca`` this package is CROSS-STACK: its collectors run once per
repo regardless of the detected stack, NOT as per-stack ``@register_adapter``
entries.

Wave 1 (Plan 12-02) ships:
    * :func:`history.collect_git_history` — HIST-01, the one-shot-per-repo
      full git-history secret collector. It reuses Plan 12-01's value-blind
      ``render.secret_lint.scan_git_history`` sibling, constructs ``[REDACTED:N]``
      Findings in the COLL-03 shape, and dedups against the working-tree finding
      set so a still-present secret is never double-counted (only
      committed-then-deleted secrets surface).
"""
from __future__ import annotations

from repo_audit.adapters.supply_chain.history import (
    HistoryResult,
    collect_git_history,
)

__all__ = [
    "HistoryResult",
    "collect_git_history",
]
