"""MOB-03 Tier-3a (9-T3a/9-T3b) — MobSF Docker static mapper (Plan 09-03, Wave 2).

Laid down in Wave 0 (Plan 09-00) as a RED-then-GREEN target. ``importorskip``
keeps the module SKIPPED until ``repo_audit.adapters.mobile.mobsf`` lands,
then these REAL assertions activate (03-01b SKIPPED->ACTIVE discipline).

Contract under test:
  * ``report_json`` (the hand-authored A4 fixture) maps to >=1 Finding with every
    raw secret from the fixture's ``secrets`` list REDACTED (T-9-04 / SC-5),
  * absent docker -> ``status == "unavailable"`` with no raise/hang (T-9-03).
"""
from __future__ import annotations

import pytest

mobsf = pytest.importorskip(
    "repo_audit.adapters.mobile.mobsf",
    reason="optional module repo_audit.adapters.mobile.mobsf not importable — feature not present in this build, or the install is incomplete",
)


def _map_report(report: dict):
    """Invoke the Wave-2 report_json mapper, tolerating naming variants."""
    for name in ("report_json_to_findings", "map_report_json", "map_mobsf_json"):
        fn = getattr(mobsf, name, None)
        if fn is not None:
            return fn(report)
    pytest.fail("mobsf exposes no report_json mapper")


def test_report_json_to_findings_redacted(mobsf_report_json):
    """report_json -> Findings; no raw secret from the fixture survives."""
    findings = _map_report(mobsf_report_json)
    assert len(findings) >= 1

    raw_secrets = list(mobsf_report_json.get("secrets") or []) + list(
        mobsf_report_json.get("possible_secrets") or []
    )
    assert raw_secrets, "fixture must seed at least one raw secret to redact"

    saw_redaction = False
    for f in findings:
        serialized = f.model_dump_json()
        for secret in raw_secrets:
            # The high-entropy VALUE portion (after any 'name : ' prefix) must
            # never appear verbatim in a serialized Finding.
            value = secret.split(" : ")[-1].split("=")[-1].strip()
            if value:
                assert value not in serialized
        if "[REDACTED:" in serialized:
            saw_redaction = True
    assert saw_redaction


def test_unavailable(fp):
    """Docker absent -> adapter returns status=='unavailable', no raise/hang."""
    if not hasattr(mobsf, "run_mobsf"):
        pytest.skip("Wave 2 run_mobsf entry point not yet landed")

    # Simulate docker being absent: any docker invocation fails to start.
    fp.register([fp.any()], callback=lambda process: (_ for _ in ()).throw(
        FileNotFoundError("docker")
    ))

    result = mobsf.run_mobsf(apk_path=None)
    assert result.status == "unavailable"
