"""Phase 2 orchestration layer.

Sits between cli.py and the collectors/walker/schema packages. Phase 3+
stack adapters plug in here (alongside scope_ledger_builder) — keeping
cli.py thin and the wiring composable.
"""
from repo_audit.orchestration.scope_ledger_builder import (
    UNIVERSAL_REQUIRED_COLLECTORS,
    auto_fill_ledger_gaps,
    build_scope_ledger,
)

__all__ = [
    "UNIVERSAL_REQUIRED_COLLECTORS",
    "auto_fill_ledger_gaps",
    "build_scope_ledger",
]
