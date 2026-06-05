"""VER-04 — a validly-refuted finding leaves the active set, lands in the Refuted
appendix WITH reason+citation, confidence dropped — never silently vanishes.

Plan 17-03 (Wave 3) implements the refuted appendix inside ``run_verification``.
"""
from __future__ import annotations

from repo_audit.verification import stage as _stage
from repo_audit.verification.record import build_finding_ref


def test_valid_refutation_to_appendix_not_vanished(fake_finding, fake_repo_with_source):
    """A validly-refuted finding lands in the appendix with reason+citation.

    The critic refutes one of two corroborated findings with a file_line citation
    that resolves against the real repo (src/app/auth.py exists, line 1 valid).
    The refuted finding must be ABSENT from active and PRESENT in refuted[] with
    its RefutationRecord (reason + citation), confidence dropped.
    """
    repo = fake_repo_with_source
    # Two identity-corroborated findings; the critic will refute the FIRST queued.
    f_a = fake_finding(
        family="sca", source_tool="osv", file="src/app/auth.py", line=1,
        severity="major", rule_id="CVE-2026-9999",
    )
    f_b = fake_finding(
        family="sca_grype", source_tool="grype", file="src/app/auth.py", line=1,
        severity="major", rule_id="CVE-2026-9999",
    )

    ref_a = build_finding_ref(f_a)

    def _refute_first_factory(*, candidate_ref: str, **_kwargs):
        from repo_audit.verification import critic as _critic

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def run_once(self):
                if candidate_ref == ref_a:
                    await _critic.submit_verdict.handler({
                        "outcome": "refuted",
                        "angle": "existing_control",
                        "citation": {"kind": "file_line", "file": "src/app/auth.py", "line": 1},
                        "reason": "guarded by an upstream control at auth.py:1",
                    })
                else:
                    await _critic.submit_verdict.handler({"outcome": "survived"})

        return _Client()

    active, refuted, records, vmeta = _stage.run_verification(
        [f_a, f_b],
        repo_path=repo,
        client_factory=_refute_first_factory,
    )

    # Nothing vanished: active + refuted accounts for every input.
    assert len(active) + len(refuted) == 2
    assert len(refuted) == 1

    # The refuted finding is ABSENT from the active set.
    active_refs = {build_finding_ref(f) for f in active}
    assert ref_a not in active_refs

    # The refuted entry carries the reason + citation (auditable, not vanished).
    entry = refuted[0]
    assert entry["finding_ref"] == ref_a
    assert "auth.py:1" in entry["reason"] or "upstream" in entry["reason"]
    assert entry["citation"]["kind"] == "file_line"
    # Confidence dropped on the refuted finding.
    assert entry["confidence_dropped"] is True


def test_accounting_invariant_nothing_vanishes(fake_finding):
    """len(active) + len(refuted) == len(input) — the core no-vanish invariant."""
    findings = [
        fake_finding(family="sca", source_tool="osv", file="src/x.py", line=1),
        fake_finding(family="sca_grype", source_tool="grype", file="src/x.py", line=1),
        fake_finding(family="sast", source_tool="semgrep", file="src/y.py", line=4),
    ]
    active, refuted, records, vmeta = _stage.run_verification(
        findings, repo_path=None, no_critic=True,
    )
    assert len(active) + len(refuted) == len(findings)
