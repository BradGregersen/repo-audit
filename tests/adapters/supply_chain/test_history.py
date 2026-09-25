"""HIST-01 — full-history git secret scan (Plan 12-02, Wave 1).

Laid down in Wave 0 (Plan 12-01) as RED-then-GREEN targets. ``importorskip``
keeps the module SKIPPED until ``repo_audit.adapters.supply_chain.history``
lands, then these assertions activate automatically (the 03-01b
SKIPPED->ACTIVE discipline).

Contract under test (RESEARCH Test Map):
  * a committed-then-deleted secret IS flagged (history walk, not working-tree),
  * a secret still present in BOTH the working tree and history is deduped
    (no double-count — Pattern 3 value-blind key),
  * every history hit renders ``[REDACTED:N]``, never a raw value,
  * no ``.git`` -> ``status == 'unavailable'`` and the scan still completes
    (SAFE-08).

The committed-then-deleted scenario uses the conftest ``secret_history_repo``
pygit2 factory (commit a secret, then a later commit deleting it).
"""
from __future__ import annotations

import shutil

import pytest

history = pytest.importorskip(
    "repo_audit.adapters.supply_chain.history",
    reason="optional module repo_audit.adapters.supply_chain.history not importable — feature not present in this build, or the install is incomplete",
)


def _collect(repo_path):
    """Invoke the Wave-1 history collector, tolerating naming variants."""
    for name in ("collect_history", "scan_history", "run_history", "collect"):
        fn = getattr(history, name, None)
        if fn is not None:
            return fn(repo_path)
    pytest.fail("supply_chain.history exposes no history collector entry point")


# real_subprocess: needs real gitleaks to detect the seeded history secret.
@pytest.mark.real_subprocess
@pytest.mark.skipif(
    shutil.which("gitleaks") is None,
    reason="needs the real gitleaks binary on PATH",
)
def test_committed_then_deleted_flagged(secret_history_repo):
    """A secret committed then later deleted is still flagged from history."""
    repo = secret_history_repo()
    result = _collect(repo)
    findings = getattr(result, "findings", result)
    assert findings, "committed-then-deleted secret must surface from history"


def test_working_tree_dup_deduped(secret_history_repo):
    """A history hit duplicating a still-present working-tree hit is deduped.

    Wave-1 owns the exact dedup wiring; this stub pins the contract name so the
    test flips ACTIVE when the module lands.
    """
    repo = secret_history_repo()
    result = _collect(repo)
    findings = getattr(result, "findings", result)
    # No two findings share the same value-blind dedup key (rule_id, file,
    # redacted_len) — Pattern 3.
    keys = []
    for f in findings:
        pv = getattr(getattr(f, "evidence", None), "parsed_value", {}) or {}
        keys.append(
            (
                getattr(f, "rule_id", "") or "",
                getattr(f, "file", "") or "",
                int(pv.get("redacted_len") or 0),
            )
        )
    assert len(keys) == len(set(keys)), f"duplicate history findings: {keys!r}"


def test_history_hit_redacted(secret_history_repo):
    """Every history finding renders [REDACTED:N], never the raw secret value."""
    secret = "AKIA" + "ZZZZ1111ZZZZ2222"
    repo = secret_history_repo(secret=secret, name="redact-history")
    result = _collect(repo)
    findings = getattr(result, "findings", result)
    for f in findings:
        serialized = f.model_dump_json()
        assert secret not in serialized, "raw secret value leaked into a Finding"
        assert "[REDACTED:" in f.evidence.output_snippet


def test_no_git_unavailable(tmp_path):
    """A directory with no .git -> status 'unavailable', scan completes (SAFE-08)."""
    no_git = tmp_path / "plain-dir"
    no_git.mkdir()
    result = _collect(no_git)
    status = getattr(result, "status", None)
    assert status == "unavailable", f"expected 'unavailable', got {status!r}"
