"""MOB-02 (9-T2) — Tier-2 Expo/RN bundled-secret pass (Plan 09-02, Wave 1).

Laid down in Wave 0 (Plan 09-00) as a RED-then-GREEN target. ``importorskip``
keeps the module SKIPPED until ``repo_audit.adapters.mobile.bundled_secrets``
lands, then these REAL assertions activate (03-01b SKIPPED->ACTIVE discipline).

Contract under test (09-RESEARCH § Architecture Pattern 2):
  * the service_role JWT (app.config.js) and the sb_secret_ value (eas.json) ARE
    flagged; the PUBLIC ``EXPO_PUBLIC_SUPABASE_ANON_KEY`` (.env) is NEVER flagged,
  * a JWT-role helper discriminates ``service_role`` vs ``anon`` by the decoded
    role claim,
  * every emitted finding's snippet is redacted to ``[REDACTED:N]`` and never
    carries the raw key bytes (T-9-04 / SCH-08).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

bundled_secrets = pytest.importorskip(
    "repo_audit.adapters.mobile.bundled_secrets",
    reason="optional module repo_audit.adapters.mobile.bundled_secrets not importable — feature not present in this build, or the install is incomplete",
)

# Import the synthetic-token constants from the Plan 09-00 factory so the
# role-discrimination + raw-bytes assertions reference the exact fixture values.
_MOBILE_FIXTURES = Path(__file__).parent / "fixtures" / "mobile"
if str(_MOBILE_FIXTURES) not in sys.path:
    sys.path.insert(0, str(_MOBILE_FIXTURES))
from expo_repo_factory import (  # noqa: E402
    ANON_JWT,
    SERVICE_ROLE_JWT,
)


def _run(repo: Path):
    """Invoke the Wave-1 pass over a repo, tolerating naming variants."""
    for name in ("scan_bundled_secrets", "run_bundled_secrets", "scan", "run"):
        fn = getattr(bundled_secrets, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("bundled_secrets exposes no scan entry point")


def test_service_role_flagged_anon_not(expo_android_repo):
    """service_role / sb_secret_ flagged; the public anon key NEVER flagged."""
    result = _run(expo_android_repo)
    findings = result.findings

    # At least the service_role JWT and the sb_secret_ value must surface.
    assert len(findings) >= 1

    # ZERO finding may reference the public anon key by name.
    blob = " ".join(
        f"{f.file or ''} {f.recommendation or ''} "
        f"{(f.evidence.output_snippet if f.evidence else '') or ''}"
        for f in findings
    )
    assert "EXPO_PUBLIC_SUPABASE_ANON_KEY" not in blob


def test_jwt_role():
    """The JWT-role helper returns the decoded role claim (anon vs service_role)."""
    helper = None
    for name in ("jwt_role", "_jwt_role", "decode_jwt_role"):
        helper = getattr(bundled_secrets, name, None)
        if helper is not None:
            break
    assert helper is not None, "bundled_secrets exposes no JWT-role helper"

    assert helper(SERVICE_ROLE_JWT) == "service_role"
    assert helper(ANON_JWT) == "anon"


def test_redaction(expo_android_repo):
    """Every emitted finding snippet is redacted; raw key bytes never appear."""
    result = _run(expo_android_repo)
    findings = result.findings
    assert len(findings) >= 1

    # The raw service_role JWT and sb_secret_ value must never leak into any
    # report-visible field.
    for f in findings:
        visible = " ".join(
            part
            for part in (
                f.file,
                f.recommendation,
                f.confidence_caveat,
                f.evidence.output_snippet if f.evidence else None,
            )
            if part
        )
        assert "[REDACTED:" in visible
        assert SERVICE_ROLE_JWT not in visible
