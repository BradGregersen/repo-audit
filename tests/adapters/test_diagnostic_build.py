"""MOB-03 Tier-3b (9-T3c/9-T3d) — diagnostic build safety (Plan 09-04, Wave 2).

Laid down in Wave 0 (Plan 09-00) as a RED-then-GREEN target. ``importorskip``
keeps the module SKIPPED until ``repo_audit.adapters.mobile.diagnostic_build``
lands, then these REAL assertions activate (03-01b SKIPPED->ACTIVE discipline).

Contract under test (09-RESEARCH § Architecture Pattern 4 — throwaway copy):
  * a post-build git-status diff that shows offenders trips a MOD-1 tripwire ->
    the adapter returns ``status == "unavailable"`` (host-independent, T-9-05),
  * (integration) a real ``./gradlew assembleDebug`` builds a COPY and leaves the
    ORIGINAL tree git-clean.
"""
from __future__ import annotations

import pytest

diagnostic_build = pytest.importorskip(
    "repo_audit.adapters.mobile.diagnostic_build",
    reason="Wave 2 (plan 09-04) not yet landed — mobile.diagnostic_build missing",
)


def _run_build(repo):
    """Invoke the Wave-2 diagnostic build, tolerating naming variants."""
    for name in ("diagnostic_build", "run_diagnostic_build", "build_apk"):
        fn = getattr(diagnostic_build, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("diagnostic_build exposes no build entry point")


def test_tripwire(expo_android_repo, monkeypatch):
    """A post-build git-status diff with offenders -> unavailable + MOD-1 note."""
    # Force the post-build snapshot diff to report offenders, regardless of any
    # real git state, so the MOD-1 tripwire path is exercised host-independently.
    monkeypatch.setattr(
        diagnostic_build,
        "snapshot_git_status",
        lambda repo_path: {"?? build/leaked-artifact"},
        raising=False,
    )

    result = _run_build(expo_android_repo)
    assert result.status == "unavailable"
    note = (result.notes or "").lower()
    assert "mod-1" in note or "git" in note or "tripwire" in note


@pytest.mark.integration
def test_build_copies_not_inplace(expo_android_repo):
    """A real assembleDebug builds a copy; the ORIGINAL tree stays git-clean."""
    import subprocess

    repo = expo_android_repo
    # Make the fixture a real git repo so git status is meaningful.
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=False)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=False)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "init"],
        check=False,
    )

    _run_build(repo)

    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain", "-uall"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert status.stdout.strip() == ""
