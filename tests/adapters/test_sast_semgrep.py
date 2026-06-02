"""SAST-01 — Semgrep collector contract (Plan 10-03, Wave 2/3).

Laid down in Wave 0 (Plan 10-00) as a RED-then-GREEN target. The opening
``pytest.importorskip`` keeps this module SKIPPED until the Wave-2 implementation
``repo_audit.adapters.sast.semgrep`` lands, at which point these assertions
activate automatically (the 03-01b SKIPPED->ACTIVE-on-landing discipline). The
assertions are REAL (never ``pass``) so the module fails RED the instant the
import resolves but the contract is not yet met.

The owasp SARIF fixture is hand-authored (Plan 10-00, PROVENANCE.md).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

semgrep = pytest.importorskip(
    "repo_audit.adapters.sast.semgrep",
    reason="Wave 2 (plan 10-03) not yet landed — sast.semgrep missing",
)

_FIXTURES = Path(__file__).parent / "fixtures"


def _load_owasp() -> dict:
    return json.loads(
        (_FIXTURES / "sast" / "owasp_top_ten.sarif").read_text(encoding="utf-8")
    )


def test_collect_semgrep_sarif_to_findings(fp, sast_vuln_repo, monkeypatch):
    """A canned semgrep SARIF invocation maps to >=1 OWASP static/candidate finding.

    Registers a canned semgrep run (via pytest-subprocess ``fp``) returning the
    owasp fixture as stdout, returncode 0, then calls ``collect_semgrep`` and
    asserts the SAST-01 finding contract: source_tool=="semgrep",
    dimension=="security", evidence_type=="static", confidence=="candidate", and
    a non-empty OWASP mapping in parsed_value.
    """
    owasp_bytes = json.dumps(_load_owasp())
    fp.register([fp.any()], stdout=owasp_bytes, returncode=0, occurrences=10)

    result = semgrep.collect_semgrep(
        sast_vuln_repo, env={}, packs=["p/owasp-top-ten"]
    )
    findings = getattr(result, "findings", result)

    assert len(findings) >= 1
    assert all(f.source_tool == "semgrep" for f in findings)
    assert all(f.dimension == "security" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    assert any(f.evidence.parsed_value.get("owasp") for f in findings), (
        "at least one finding must carry a non-empty OWASP mapping"
    )


def test_unavailable(monkeypatch, sast_vuln_repo):
    """resolve_tool returning None -> status=='unavailable', no raise, no hang."""
    monkeypatch.setattr(semgrep, "resolve_tool", lambda *a, **k: None, raising=False)

    result = semgrep.collect_semgrep(
        sast_vuln_repo, env={}, packs=["p/owasp-top-ten"]
    )
    status = getattr(result, "status", None)
    assert status == "unavailable"


@pytest.mark.integration
def test_live_semgrep(sast_vuln_repo):
    """Live Semgrep over the vuln fixture -> >=1 OWASP static/candidate finding (SAST-01).

    Skips cleanly when the semgrep binary is not resolvable; otherwise runs the
    real collector with ``--config p/owasp-top-ten --sarif --metrics off`` over
    the synthetic OS-command-injection repo and asserts >=1 OWASP-mapped
    static/candidate finding.
    """
    if not hasattr(semgrep, "run_semgrep"):
        pytest.skip("Wave 2 run_semgrep entry point not yet landed")

    result = semgrep.run_semgrep(sast_vuln_repo, packs=["p/owasp-top-ten"])
    status = getattr(result, "status", None)
    if status in {"unavailable", "timeout"}:
        pytest.skip("semgrep binary not resolvable in this environment")

    findings = getattr(result, "findings", result)
    assert any(
        f.evidence_type == "static"
        and f.confidence == "candidate"
        and f.evidence.parsed_value.get("owasp")
        for f in findings
    ), "live semgrep must produce >=1 OWASP-mapped static/candidate finding"
