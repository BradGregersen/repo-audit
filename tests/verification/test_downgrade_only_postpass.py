"""VER-05 / SC5 — downgrade-only post-pass: the critic may lower severity/confidence
but NEVER promotes static/heuristic → runtime/exploitable; runtime is born-runtime
only (SAFE-01, D-17-16).

Plan 17-03 (Wave 3) implements the downgrade-only post-pass inside
``run_verification`` (cloned from the scan_runner DAST guard).
"""
from __future__ import annotations

from repo_audit.verification import stage as _stage
from repo_audit.verification.record import build_finding_ref


def test_no_static_to_runtime_promotion(fake_finding, monkeypatch):
    """A finding 'promoted' to runtime is reverted/dropped + ledger-noted; never raises.

    We simulate a buggy stage-2 that flips a static finding's evidence_type to
    'runtime' (the exact thing the post-pass exists to catch). The post-pass must
    detect the static→runtime smuggle, drop/revert it, record a violation, and
    NEVER raise.
    """
    f_static = fake_finding(
        family="sast", source_tool="semgrep", evidence_type="static",
        file="src/app.py", line=5, severity="major",
    )

    # Monkeypatch the critic application step to smuggle a runtime promotion.
    original = _stage._apply_verdicts

    def _smuggle(findings, verdicts, records, *, pre_evidence):
        active, refuted = original(findings, verdicts, records, pre_evidence=pre_evidence)
        # Buggy promotion: a born-static finding now claims runtime.
        smuggled = [f.model_copy(update={"evidence_type": "runtime"}) for f in active]
        return smuggled, refuted

    monkeypatch.setattr(_stage, "_apply_verdicts", _smuggle)

    # Must not raise.
    active, refuted, records, vmeta = _stage.run_verification(
        [f_static], repo_path=None, no_critic=True,
    )

    # The smuggled runtime promotion was reverted/dropped: no surviving active
    # finding may carry evidence_type='runtime' it was not born with.
    for f in active:
        assert f.evidence_type != "runtime"

    # A violation was recorded for disclosure (folded into a ledger note upstream).
    assert vmeta.get("downgrade_violations", 0) >= 1


def test_born_runtime_finding_is_not_a_violation(fake_finding):
    """A finding BORN runtime is legitimate — the post-pass does NOT flag it.

    Only a static/heuristic finding that GAINED runtime is a violation; a
    genuinely born-runtime finding passes the post-pass untouched.
    """
    f_runtime = fake_finding(
        family="rls", source_tool="pgrls", evidence_type="runtime",
        file="supabase/p.sql", line=1,
    )
    active, refuted, records, vmeta = _stage.run_verification(
        [f_runtime], repo_path=None, no_critic=True,
    )
    assert len(active) == 1
    assert active[0].evidence_type == "runtime"
    assert vmeta.get("downgrade_violations", 0) == 0


def test_never_raises_on_stage_failure(fake_finding, monkeypatch):
    """D-25: any exception inside the stage leaves findings at deterministic rungs
    and run_verification still returns the full tuple."""
    f = fake_finding(family="sca", source_tool="osv", file="src/z.py", line=1)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated stage-1 explosion")

    monkeypatch.setattr(_stage, "tiered_corroborate", _boom)

    # Must not raise; returns the input findings at their deterministic rungs.
    active, refuted, records, vmeta = _stage.run_verification(
        [f], repo_path=None, no_critic=True,
    )
    assert len(active) + len(refuted) == 1
