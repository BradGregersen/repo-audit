"""CodeQL use-rights provenance contract (DSAST-01, Plan 16-04).

Pins the provenance stamping:
  * a SUCCESSFUL CodeQL run records the chosen use_rights ground in a provenance
    note ("ran CodeQL under <ground> attestation") — never invented;
  * an UNAVAILABLE run records NO provenance entry (mirror build_sast_provenance's
    one-entry-on-success discipline).
"""
from __future__ import annotations

from repo_audit.adapters.sast.provenance import build_codeql_provenance


def test_use_rights_ground_stamped():
    """A successful run stamps the chosen ground into the provenance note."""
    entries = build_codeql_provenance(
        status="ok", use_rights="personal-own-code"
    )
    assert len(entries) == 1
    note = entries[0].note.lower()
    assert "codeql" in note
    assert "personal-own-code" in note
    assert "attestation" in note


def test_each_ground_stamped_verbatim():
    for ground in ("oss", "ghas", "personal-own-code"):
        entries = build_codeql_provenance(status="ok", use_rights=ground)
        assert len(entries) == 1
        assert ground in entries[0].note


def test_unavailable_run_no_entry():
    """An unavailable/timeout run contributes NO provenance entry."""
    assert build_codeql_provenance(status="unavailable", use_rights="ghas") == []
    assert build_codeql_provenance(status="timeout", use_rights="ghas") == []


def test_no_ground_no_entry():
    """No ground (shouldn't happen on success) -> no entry, never invents one."""
    assert build_codeql_provenance(status="ok", use_rights=None) == []
