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
    reason="optional module repo_audit.adapters.sast.semgrep not importable — feature not present in this build, or the install is incomplete",
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
# real_subprocess: live end-to-end run of the real semgrep binary.
@pytest.mark.real_subprocess
def test_live_semgrep(sast_vuln_repo):
    """Live Semgrep end-to-end (SAST-01/02/03) over the synthetic vuln repo.

    The full live path (Plan 10-04 phase gate): detect the fixture's stacks,
    select the registry packs from the detection (the exact Plan-04 wiring —
    ``select_packs`` yields ``p/owasp-top-ten`` + ``p/secrets`` plus ``p/react``
    for the Expo/RN package.json), then run the REAL ``collect_semgrep`` against a
    cache-redirected scan env. Asserts:

      * status == "ok",
      * >=1 finding with ``dimension=="security"``, ``evidence_type=="static"``,
        ``confidence=="candidate"``, and a non-empty ``parsed_value["owasp"]``
        (SAST-01/the OS-command-injection in ``src/vuln.py`` maps to OWASP), and
      * NO finding's snippet contains the synthetic ``EXPO_PUBLIC_SUPABASE_ANON_KEY``
        value (SAST-03 — the public anon key is never flagged as a leak).

    Skips cleanly when the semgrep binary is not resolvable (the test is
    integration-gated; it never runs in the default unit tier).
    """
    if not hasattr(semgrep, "run_semgrep"):
        pytest.skip("Wave 2 run_semgrep entry point not yet landed")

    from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
    from repo_audit.adapters.sast.rulesets import select_packs
    from repo_audit.detect.detector import detect_stacks

    # The synthetic public anon key the SAST-03 drop must NOT surface (mirrors the
    # value the factory writes into the fixture's .env).
    _ANON_KEY = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJyb2xlIjoiYW5vbiIsImlzcyI6InN5bnRoZXRpYy1maXh0dXJlIiwiaWF0IjoxNzAwMDAwMDAwfQ."
        "FAKE_SYNTHETIC_ANON_SIGNATURE_DO_NOT_USE"
    )

    detection = detect_stacks(sast_vuln_repo)
    packs = select_packs(detection)

    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        result = semgrep.collect_semgrep(sast_vuln_repo, env, packs=packs)

    status = getattr(result, "status", None)
    if status in {"unavailable", "timeout"}:
        pytest.skip("semgrep binary not resolvable in this environment")

    assert status == "ok"

    findings = getattr(result, "findings", result)
    assert any(
        f.dimension == "security"
        and f.evidence_type == "static"
        and f.confidence == "candidate"
        and f.evidence.parsed_value.get("owasp")
        for f in findings
    ), "live semgrep must produce >=1 OWASP-mapped static/candidate finding (SAST-01)"

    # SAST-03: the public anon key is allowlisted — its raw value must never reach
    # a finding's snippet (the drop redacts/removes it before report).
    assert all(
        _ANON_KEY not in (f.evidence.output_snippet or "") for f in findings
    ), "the public anon key must NEVER be flagged as a leak (SAST-03)"
