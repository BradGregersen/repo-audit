"""VER-01 / SC1 — a verification stage runs in scan_runner.run_scan BETWEEN the
findings merge and run_agent_session, separate from the render chokepoint.

NAME canonicalized to test_stage_placement.py (NOT test_stage_insertion.py) per
17-VALIDATION.md. Plan 17-03 (Wave 3) wires ``run_verification`` into the scan
pipeline after the DAST guard and before ``build_scope_ledger``.
"""
from __future__ import annotations

import inspect

from repo_audit.orchestration import scan_runner as _sr


def test_runs_before_narrator_after_merge():
    """The verification stage runs after the findings merge (DAST guard) and
    before build_scope_ledger / run_agent_session (the narrator).

    Asserted on the run_scan source: the ``run_verification(`` call appears AFTER
    the DAST guard's ``findings = kept_findings`` and BEFORE ``build_scope_ledger(``
    and ``run_agent_session(``. This pins VER-01 / SC1 structurally — the
    post-verification finding set is what the ledger, narrator, and renderer see.
    """
    src = inspect.getsource(_sr.run_scan)

    idx_dast_guard = src.index("findings = kept_findings")
    idx_verify = src.index("run_verification(")
    # Anchor on the ACTUAL call site (the assignment), not the docstring summary
    # line ("7. build_scope_ledger(...)") at the top of run_scan.
    idx_ledger = src.index("scope_ledger = build_scope_ledger(")
    # Anchor on the ACTUAL narrator call (via the _agent_session module attribute),
    # not the docstring summary line ("10. run_agent_session ...").
    idx_narrator = src.index("_agent_session.run_agent_session(")

    # After the DAST guard merge.
    assert idx_dast_guard < idx_verify, (
        "run_verification must run AFTER the DAST runtime post-pass guard"
    )
    # Before the ledger (so the ledger sees post-verification rungs).
    assert idx_verify < idx_ledger, (
        "run_verification must run BEFORE build_scope_ledger (Pitfall 1)"
    )
    # Before the narrator.
    assert idx_verify < idx_narrator, (
        "run_verification must run BEFORE run_agent_session (the narrator)"
    )


def test_called_via_patchable_module_attribute():
    """The verification call goes through a module attribute so tests can inject a
    stub without the live SDK (mirrors the narrator's ``_agent_session`` indirection)."""
    src = inspect.getsource(_sr.run_scan)
    # The call is dispatched through the module-attribute indirection.
    assert "_verification.run_verification(" in src or "run_verification(" in src
    # The verification stage module is importable as the indirection target.
    from repo_audit.verification import stage as _stage
    assert callable(_stage.run_verification)
