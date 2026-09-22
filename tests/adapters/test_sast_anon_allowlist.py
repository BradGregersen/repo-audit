"""SAST-03 — anon-allowlist drop + redaction + RLS cross-link (Plan 10-02).

Laid down in Wave 0 (Plan 10-00) as a RED-then-GREEN target. The opening
``pytest.importorskip`` keeps this module SKIPPED until the Wave-2 implementation
``repo_audit.adapters.sast.anon`` lands. Assertions are REAL (never
``pass``) so the module fails RED the instant the import resolves.

The drop reuses ``footguns._ANON_ALLOWLIST`` / ``footguns._redact_span``
verbatim: the PUBLIC anon key (which belongs in the client) is dropped, a genuine
secret is kept + REDACTED, and the disposition attaches an "is RLS enforced?"
cross-link.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

anon = pytest.importorskip(
    "repo_audit.adapters.sast.anon",
    reason="optional module repo_audit.adapters.sast.anon not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters.sarif.parser import sarif_to_findings

_FIXTURES = Path(__file__).parent / "fixtures"

# The synthetic raw secret bytes carried in secrets_anon.sarif — no kept finding
# may echo these verbatim (every retained snippet must be [REDACTED:N]).
_RAW_ANON_SIG = "FAKE_SYNTHETIC_ANON_SIGNATURE_DO_NOT_USE"
_RAW_SERVICE_ROLE_SIG = "FAKE_SYNTHETIC_SERVICE_ROLE_SIGNATURE_DO_NOT_USE"


def _load_secrets() -> dict:
    return json.loads(
        (_FIXTURES / "sast" / "secrets_anon.sarif").read_text(encoding="utf-8")
    )


def _parse() -> list:
    return sarif_to_findings(
        _load_secrets(),
        source_tool="semgrep",
        default_dimension="security",
        severity_map={},
    )


def test_anon_key_dropped():
    """The anon-key finding is dropped; the genuine secret remains."""
    findings = _parse()
    kept = anon.drop_anon_key_secrets(findings)
    kept_files = {f.file for f in kept}

    # The PUBLIC anon key in .env (allowlist-matching) is GONE.
    assert ".env" not in kept_files
    # The genuine service_role secret in src/config.ts REMAINS.
    assert "src/config.ts" in kept_files


def test_raw_value_never_in_finding():
    """No kept finding's serialized form contains the raw secret bytes."""
    findings = _parse()
    kept = anon.drop_anon_key_secrets(findings)

    for finding in kept:
        blob = finding.model_dump_json()
        assert _RAW_ANON_SIG not in blob
        assert _RAW_SERVICE_ROLE_SIG not in blob
        # Every retained snippet shows the value-blind redaction marker.
        assert "[REDACTED:" in finding.evidence.output_snippet


def test_rls_cross_link():
    """The SAST-03 disposition attaches an RLS cross-link (replaces the anon flag)."""
    findings = _parse()
    kept = anon.drop_anon_key_secrets(findings)

    genuine = next(f for f in kept if f.file == "src/config.ts")
    cross_link = genuine.evidence.parsed_value.get("cross_link")
    assert cross_link is not None
    # The "is RLS enforced?" cross-link must reference RLS.
    assert "RLS" in json.dumps(cross_link)
