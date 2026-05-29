"""Wave 0 stub for SAFE-06, D-69.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_corroborated_when_two_tools             (SAFE-06/D-69 — corroborated when 2 tools agree)
- test_uncorroborated_with_caveat_render_class (D-69 — uncorroborated → caveat render class)
- test_render_classes                          (D-69 — 2x2 render-class grid)
- test_agent_dispute_logged                    (D-69 — meta.agent_corroboration_disputes)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.corroboration",
    reason="Wave 1+ plan 04-07 has not landed yet — Wave 0 stub.",
)


def test_corroborated_when_two_tools():
    """SAFE-06/D-69: a finding is corroborated when two tools agree."""
    pass


def test_uncorroborated_with_caveat_render_class():
    """D-69: an uncorroborated finding uses the caveat render class."""
    pass


def test_render_classes():
    """D-69: the 2x2 render-class grid resolves correctly."""
    pass


def test_agent_dispute_logged():
    """D-69: agent disputes are logged to meta.agent_corroboration_disputes."""
    pass
