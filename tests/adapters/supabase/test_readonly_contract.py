"""SC-5 read-only contract + CRIT-4 integration test (Plan 08-05, Task 3).

A LIVE ``--rls-pgrls`` scan (deliberately WITHOUT ``--rls-runtime``, so the live
Supabase project is never touched — T-08-22) against a repo built from adapt's
real SQL. Proves the phase's two hardest structural guarantees:

  * **SC-5 (read-only):** post-flight ``git status --porcelain -uall`` on the
    target repo is EMPTY — the ephemeral PG + temp SQL leave the repo untouched
    (T-08-18); the ephemeral supabase/postgres container is torn down — no orphan
    remains (T-08-21).
  * **CRIT-4 (no overclaim):** because ``--rls-runtime`` was absent, the rendered
    report shows the honest "runtime test not run" line and NO static finding
    carries an enforcement word (T-08-19).

Docker-gated + adapt-gated: skips cleanly when the daemon or adapt are absent.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15, check=False
        )
        return proc.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _supabase_pg_container_ids() -> set[str]:
    ps = subprocess.run(
        ["docker", "ps", "-q", "--no-trunc",
         "--filter", "ancestor=supabase/postgres"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    return set(ps.stdout.split())


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )


def _build_committed_repo(tmp_path: Path, adapt_sql_dir: Path) -> Path:
    """Build a committed git repo holding adapt's real SQL (legacy layout)."""
    repo = tmp_path / "fake_supabase_repo"
    sql_dst = repo / "packages" / "api-client" / "sql"
    sql_dst.mkdir(parents=True)
    for src in sorted(adapt_sql_dir.glob("[0-9][0-9][0-9]_*.sql")):
        shutil.copy(src, sql_dst / src.name)
    # A config.toml pinning the PG major (adapt is 17).
    (repo / "supabase").mkdir(parents=True, exist_ok=True)
    (repo / "supabase" / "config.toml").write_text(
        "[db]\nmajor_version = 17\n", encoding="utf-8"
    )
    (repo / "README.md").write_text("# fake supabase repo\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    return repo


# Banned static enforcement words (CRIT-4) — the same vocabulary the verify-
# phrasing tripwire polices. Only a runtime-evidenced PASS line may use them, and
# this scan has no --rls-runtime, so none may appear in the rendered report's
# static finding rows.
_ENFORCEMENT_RE = re.compile(r"\b(enforced|secure|protected)\b", re.IGNORECASE)


def test_rls_pgrls_scan_is_read_only_and_makes_no_enforcement_claim(
    tmp_path, adapt_sql_dir
):
    """Full ``repo-audit scan --rls-pgrls`` proves SC-5 + CRIT-4 (no --rls-runtime)."""
    if not _docker_available():
        pytest.skip("docker daemon not available")

    from typer.testing import CliRunner

    from repo_audit.cli import app
    from repo_audit.meta.git_status import (
        diff_git_status,
        snapshot_git_status,
    )

    repo = _build_committed_repo(tmp_path, adapt_sql_dir)

    before_containers = _supabase_pg_container_ids()
    pre_status = snapshot_git_status(repo)

    runner = CliRunner()
    # NO --rls-runtime: the live Supabase project is never touched (T-08-22).
    result = runner.invoke(
        app, ["scan", str(repo), "--no-agent", "--rls-pgrls"]
    )
    assert result.exit_code == 0, f"scan failed: {result.output}"

    # (a) SC-5 read-only: diff_git_status(pre, post) is EMPTY (zero target-repo
    # modifications outside docs/state-reports/). porcelain -uall.
    post_status = snapshot_git_status(repo)
    offenders = diff_git_status(pre_status, post_status)
    assert offenders == [], (
        f"SC-5 read-only contract broken — files modified outside "
        f"docs/state-reports/: {offenders}"
    )

    # (b) no orphan supabase/postgres container remains after the scan (T-08-21).
    after_containers = _supabase_pg_container_ids()
    leaked = after_containers - before_containers
    assert not leaked, f"orphan supabase/postgres container(s): {leaked}"

    # (c) the rendered report has the data-privacy/RLS section + the honest
    # "runtime test not run" line (since --rls-runtime was absent).
    md_files = sorted((repo / "docs" / "state-reports").glob("*.md"))
    assert md_files, "expected a rendered state-report markdown sidecar"
    report_md = md_files[-1].read_text(encoding="utf-8")
    assert "Data privacy & RLS" in report_md
    assert re.search(r"runtime.*not run", report_md, re.IGNORECASE), (
        "expected the honest 'runtime test not run' line (no --rls-runtime)"
    )

    # (d) CRIT-4: NO static finding row carries an enforcement word. The runtime
    # not-run line itself must not claim enforcement; scan the finding-table
    # region (everything below the data-privacy heading through the next H2).
    section = report_md.split("### 6a. Data privacy & RLS", 1)[-1]
    section = section.split("\n## ", 1)[0]
    # Allow the literal "no enforcement claim is made" disclaimer — strip the
    # word 'enforcement' from that benign phrase before scanning for overclaims.
    scanned = section.replace("enforcement", "")
    matches = _ENFORCEMENT_RE.findall(scanned)
    assert not matches, (
        f"CRIT-4 violated — static RLS report prose carried enforcement "
        f"word(s) without a runtime test: {matches}"
    )
