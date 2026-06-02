"""Mobile adapter package — native + JS mobile security collectors (Phase 9).

Wave-1 surface (Plan 09-01): the Tier-1 no-build ``mobsfscan`` collector over the
native Android source. Re-exported here so callers import from the package root.

WIRING NOTE: ``run_mobile`` + ``@register_adapter("mobile")`` are owned by
Plan 05 — they are intentionally NOT defined here yet, to avoid a half-wired
adapter that the orchestrator would pick up before its full composition (native
mobsfscan + JS bundled-secrets + MobSF + diagnostic build) lands. Until then this
package exposes only the individual collectors.
"""
from __future__ import annotations

from repo_audit.adapters.mobile.mobsfscan import (
    collect_mobsfscan,
    run_mobsfscan,
)

__all__ = ["collect_mobsfscan", "run_mobsfscan"]
