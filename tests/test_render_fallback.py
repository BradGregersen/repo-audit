"""Wave 0 stub for D-67 (agent-unavailable fallback rendering).

The renderer module exists today, so there is no module to importorskip.
Instead this module guards on the *presence of the `agent_status` field on
ReportMeta*: that field lands in a later Wave (the agent meta-capture plan),
so until then the whole module SKIPs cleanly and flips ACTIVE automatically
once the field is wired. This mirrors the Phase 3 importorskip discipline
for a contract gated on a schema field rather than an importable module.

Do NOT replace the skip guard or the `pass` bodies in this Wave 0 task —
Waves 2-4 own the fallback rendering; this task only pins contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_fallback_dimensions_render_pending   (D-67 — meta.agent_status='unavailable_*' → dims render D-09 pending)
- test_fallback_exec_summary_renders_pending (D-67 — exec summary renders pending)
- test_fallback_exit_code_zero               (D-67 — exit 0 honesty contract)
"""
from __future__ import annotations

import pytest


def _agent_status_field_landed() -> bool:
    """True once the agent meta-capture plan adds ReportMeta.agent_status."""
    from repo_audit.schema.report import ReportMeta

    return "agent_status" in ReportMeta.model_fields


pytestmark = pytest.mark.skipif(
    not _agent_status_field_landed(),
    reason="agent meta-capture plan has not landed yet (ReportMeta.agent_status absent) — Wave 0 stub.",
)


def test_fallback_dimensions_render_pending():
    """D-67: meta.agent_status='unavailable_*' → each dimension renders the pending marker."""
    pass


def test_fallback_exec_summary_renders_pending():
    """D-67: the executive summary renders the pending marker on fallback."""
    pass


def test_fallback_exit_code_zero():
    """D-67: the exit code is 0 on agent-unavailable fallback (honesty contract)."""
    pass
