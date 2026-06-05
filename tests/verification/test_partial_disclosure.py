"""CRIT-5 — "N of M findings critically reviewed" disclosed in the report; no
silent cap.

Plan 17-03 (Wave 3) carries the N-of-M disclosure into ReportMeta
(critic_reviewed / critic_total_queue), and the verification stage surfaces it
in the verification_meta. On budget exhaustion N < M.
"""
from __future__ import annotations

from repo_audit.schema.report import ReportMeta, ScanReport


def test_n_of_m_disclosed():
    """ReportMeta exposes the N-of-M critic-review disclosure (additive Optional).

    The three additive Optional fields default to None so a Phase 1-16 sidecar
    round-trips; when the verification stage runs they carry the disclosure.
    """
    # Default construction (no verification): the fields are absent (None).
    meta_default = ReportMeta(
        repo_slug="x",
        commit_sha="UNCOMMITTED",
        scan_date="2026-06-05",
        tool_version="0",
    )
    assert meta_default.critic_reviewed is None
    assert meta_default.critic_total_queue is None
    assert meta_default.refuted_findings is None

    # Populated disclosure: 3 of 10 reviewed (budget exhausted → N < M).
    meta = ReportMeta(
        repo_slug="x",
        commit_sha="UNCOMMITTED",
        scan_date="2026-06-05",
        tool_version="0",
        critic_reviewed=3,
        critic_total_queue=10,
        refuted_findings=[{"finding_ref": "t::r::f:1", "reason": "dup", "citation": None}],
    )
    assert meta.critic_reviewed == 3
    assert meta.critic_total_queue == 10
    assert meta.critic_reviewed < meta.critic_total_queue  # N < M on exhaustion
    assert meta.refuted_findings[0]["finding_ref"] == "t::r::f:1"

    # schema_version stays "1" — the additive Optional fields are forward-compatible.
    report = ScanReport(meta=meta)
    assert report.schema_version == "1"


def test_schema_version_stays_one_with_verification_fields():
    """Adding the verification fields must NOT bump schema_version (D-21)."""
    assert ReportMeta.model_fields["critic_reviewed"].default is None
    # The literal schema_version is still "1".
    assert ScanReport.model_fields["schema_version"].default == "1"


def test_stage_meta_carries_n_of_m(fake_finding):
    """run_verification's verification_meta surfaces critic_reviewed/critic_total_queue."""
    from repo_audit.verification import stage as _stage

    def _survived_factory(*, candidate_ref: str, **_kwargs):
        from repo_audit.verification import critic as _critic

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def run_once(self):
                await _critic.submit_verdict.handler({"outcome": "survived"})

        return _Client()

    f_a = fake_finding(family="sca", source_tool="osv", file="src/a.py", line=1)
    f_b = fake_finding(family="sca_grype", source_tool="grype", file="src/a.py", line=1)
    _active, _refuted, _records, vmeta = _stage.run_verification(
        [f_a, f_b], repo_path=None, client_factory=_survived_factory,
    )
    assert "critic_reviewed" in vmeta
    assert "critic_total_queue" in vmeta
    assert vmeta["critic_reviewed"] <= vmeta["critic_total_queue"]
