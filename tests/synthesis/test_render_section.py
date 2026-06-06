"""SYN-02 — "What matters most" renders right after the exec summary; the
`--no-agent` degrade branch still renders the deterministic section.

Targets the Wave-3 render symbol (`synthesis.render`), not built in plan 18-01.
`importorskip` until the render section lands.
"""
from __future__ import annotations

import pytest

_render = pytest.importorskip(
    "repo_audit.synthesis.render",
    reason="Wave 3 synthesis.render not yet implemented (plan 18-02+)",
)


def test_what_matters_most_section_placement():
    # The section renders immediately after the exec summary, each item linking a
    # real finding id + file:line (SC3/D-18-09).
    out = _render.render_what_matters_most(  # pragma: no cover - skipped until W3
        top_findings=[{"finding_ref": "osv::CVE-X::pkg/a.ts:10", "why_it_matters": "x"}],
    )
    assert "pkg/a.ts:10" in out


def test_no_agent_section_renders():
    # --no-agent still renders the deterministic section with empty why_it_matters.
    out = _render.render_what_matters_most(  # pragma: no cover - skipped until W3
        top_findings=[{"finding_ref": "osv::CVE-X::pkg/a.ts:10", "why_it_matters": ""}],
    )
    assert "pkg/a.ts:10" in out
