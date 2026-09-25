"""Plan 08-02 Task 3 — pgproof lifecycle + the RLS-01 floor entry.

Two tiers:

  * **Unit (offline)** — prove ``collect_rls_static`` NEVER raises and degrades
    to ``status="unavailable"`` on every failure mode (no migrations, docker
    absent, image unpullable, apply failure) by monkeypatching the lifecycle.
    Also pin the image-pin discipline (sha256 digests, no stock-postgres).
  * **Integration (``-m integration``, docker-gated)** — stand up the real
    pinned image, apply the example app's REAL ``numbered_*.sql``, run splinter, assert
    >=1 row and that the migrations apply cleanly (A1/A3). Skips cleanly when
    docker or the example app are absent. Asserts no orphan container after the block.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from repo_audit.adapters.supabase import pgproof
from repo_audit.adapters.supabase.pgproof import (
    SUPABASE_PG_IMAGES,
    EphemeralPgUnavailable,
    MigrationApplyFailed,
    collect_rls_static,
)


# --- Image-pin discipline (static, no docker) -----------------------------

def test_all_images_pinned_by_digest():
    """Every shipped image is pinned by tag@sha256:digest (D-08-09/FND-03)."""
    assert SUPABASE_PG_IMAGES, "must ship at least one pinned image"
    for major, image in SUPABASE_PG_IMAGES.items():
        assert image.startswith("supabase/postgres:"), image
        assert "@sha256:" in image, f"major {major} not digest-pinned: {image}"


def test_no_stock_postgres_fallback_in_source():
    """No stock-postgres image string anywhere in pgproof (D-08-10)."""
    src = Path(pgproof.__file__).read_text(encoding="utf-8")
    # Only supabase/postgres images may appear — never a bare `postgres:NN`.
    import re

    # A stock image reference would look like `"postgres:16"` / `postgres:15.x`
    # WITHOUT the `supabase/` org prefix. Mask the supabase ones first.
    masked = src.replace("supabase/postgres", "")
    assert not re.search(r"\bpostgres:1[0-9]\b", masked), (
        "stock-postgres image reference found — D-08-10 forbids a fallback"
    )


# --- Never-raises floor: every failure → unavailable ----------------------

def test_no_migrations_returns_unavailable(tmp_path, fake_supabase_repo):
    """layout='none' → unavailable, never raises, never starts a container."""
    repo = fake_supabase_repo(
        tmp_path, supabase_layout=False, api_client_layout=False
    )
    result = collect_rls_static(repo)
    assert result.status == "unavailable"
    assert "no migrations" in result.notes.lower()
    assert result.findings == []


def test_docker_absent_returns_unavailable(tmp_path, fake_supabase_repo, monkeypatch):
    """ephemeral lifecycle raising EphemeralPgUnavailable → unavailable row."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)

    def _boom(*_a, **_k):
        raise EphemeralPgUnavailable("docker daemon is not running")

    monkeypatch.setattr(pgproof, "ephemeral_supabase_pg", _boom)
    result = collect_rls_static(repo)
    assert result.status == "unavailable"
    assert "stock-postgres" in result.notes  # documents the no-fallback posture
    assert result.findings == []


def test_apply_failure_degrades_whole_dimension(tmp_path, fake_supabase_repo, monkeypatch):
    """A MigrationApplyFailed → whole-dimension unavailable (no partial lint)."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)
    bad = repo / "supabase" / "migrations" / "0002_policies.sql"

    def _boom(*_a, **_k):
        raise MigrationApplyFailed(bad, 'ERROR: syntax error at or near "x"')

    monkeypatch.setattr(pgproof, "ephemeral_supabase_pg", _boom)
    result = collect_rls_static(repo)
    assert result.status == "unavailable"
    assert "0002_policies.sql" in result.notes
    assert result.findings == []


def test_unexpected_exception_is_caught(tmp_path, fake_supabase_repo, monkeypatch):
    """An arbitrary exception in the lifecycle still degrades, never raises."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)

    def _boom(*_a, **_k):
        raise RuntimeError("something unexpected")

    monkeypatch.setattr(pgproof, "ephemeral_supabase_pg", _boom)
    result = collect_rls_static(repo)
    assert result.status == "unavailable"
    assert result.findings == []


def test_success_path_maps_findings(tmp_path, fake_supabase_repo, monkeypatch):
    """A stubbed lifecycle + stubbed splinter → ok with mapped findings."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)

    from contextlib import contextmanager

    @contextmanager
    def _fake_lifecycle(*_a, **_k):
        yield "postgresql://test:test@localhost:5432/test"

    def _fake_run_splinter(_dsn, **_k):
        return [
            {
                "name": "rls_disabled_in_public",
                "title": "RLS Disabled in Public",
                "level": "ERROR",
                "facing": "EXTERNAL",
                "categories": ["SECURITY"],
                "description": "desc",
                "detail": "Table public.tasks is public.",
                "remediation": "https://example/lint",
                "metadata": {"schema": "public", "name": "tasks"},
                "cache_key": "k",
            }
        ]

    monkeypatch.setattr(pgproof, "ephemeral_supabase_pg", _fake_lifecycle)
    monkeypatch.setattr(pgproof, "run_splinter", _fake_run_splinter)
    result = collect_rls_static(repo)
    assert result.status == "ok"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "rls_disabled_in_public"
    assert f.severity == "major"  # ERROR capped at major (SCH-04)
    assert f.evidence_type == "static"
    assert "layout=supabase/migrations" in result.notes


def test_splinter_sql_unavailable_is_unavailable_not_unexpected(
    tmp_path, fake_supabase_repo, monkeypatch
):
    """No lint set (offline / bad hash) → unavailable, naming the URL."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)

    from contextlib import contextmanager

    from repo_audit.adapters.supabase.splinter_fetch import (
        SPLINTER_URL,
        SplinterSqlUnavailable,
    )

    @contextmanager
    def _fake_lifecycle(*_a, **_k):
        yield "postgresql://test:test@localhost:5432/test"

    def _unavailable(_dsn, **_k):
        raise SplinterSqlUnavailable(
            f"splinter.sql unavailable: could not fetch {SPLINTER_URL} into "
            "/cache/repo-audit/splinter/splinter.sql: URLError: offline"
        )

    monkeypatch.setattr(pgproof, "ephemeral_supabase_pg", _fake_lifecycle)
    monkeypatch.setattr(pgproof, "run_splinter", _unavailable)
    result = collect_rls_static(repo)
    assert result.status == "unavailable"
    assert result.findings == []
    assert SPLINTER_URL in result.notes
    assert "unexpectedly" not in result.notes


# --- Live integration (docker-gated; skips cleanly) -----------------------

def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.integration
def test_live_applies_example_app_sql_and_runs_splinter(tmp_path, example_app_sql_dir):
    """Apply the example app's REAL numbered_*.sql against the pinned image, run splinter.

    Requires docker + the example app present. ``example_app_sql_dir`` skips when the example app is
    absent; the docker check below skips when the daemon is down.
    """
    if not _docker_available():
        pytest.skip("docker daemon not available")

    from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
    from repo_audit.adapters.supabase.pgproof import (
        SUPABASE_PG_IMAGES,
        ephemeral_supabase_pg,
    )
    from repo_audit.adapters.supabase.splinter_collect import (
        map_splinter_rows,
        run_splinter,
    )

    def _supabase_pg_container_ids() -> set[str]:
        ps = subprocess.run(
            ["docker", "ps", "-q", "--no-trunc",
             "--filter", "ancestor=supabase/postgres"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        return set(ps.stdout.split())

    # Build a repo that points discovery at the example app's real SQL by copying the
    # numbered files into a legacy-layout dir under tmp_path.
    sql_dst = tmp_path / "packages" / "api-client" / "sql"
    sql_dst.mkdir(parents=True)
    for src in sorted(example_app_sql_dir.glob("[0-9][0-9][0-9]_*.sql")):
        shutil.copy(src, sql_dst / src.name)
    migrations = sorted(sql_dst.glob("[0-9][0-9][0-9]_*.sql"), key=lambda p: p.name)
    assert migrations, "expected example-app numbered SQL files"

    # the example app's config.toml says major 17; ensure the image is one we ship.
    pg_major = 17 if 17 in SUPABASE_PG_IMAGES else next(iter(SUPABASE_PG_IMAGES))

    before_ids = _supabase_pg_container_ids()

    with scan_tempdir() as td:
        env = build_scan_env(td)
        with ephemeral_supabase_pg(
            migrations,
            pg_major=pg_major,
            env=env,
            cwd=td,
            timeout_seconds=600.0,
        ) as dsn:
            rows = run_splinter(dsn, timeout_seconds=120.0)
            findings = map_splinter_rows(rows)

    # A1/A3: the example app's real SQL applied cleanly and splinter returned rows.
    assert len(rows) >= 1
    assert len(findings) == len(rows)
    assert all(f.source_tool == "splinter" for f in findings)

    # Teardown: no NEW supabase/postgres container is left running after the
    # block (Ryuk + the `with` exit must have removed the one we started).
    after_ids = _supabase_pg_container_ids()
    leaked = after_ids - before_ids
    assert not leaked, f"orphan supabase/postgres container(s) left running: {leaked}"
