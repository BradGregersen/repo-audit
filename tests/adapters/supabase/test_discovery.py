"""Plan 08-02 Task 1 — dual-layout migration discovery + config.toml major parse.

These tests drive ``discovery.find_migrations`` and ``discovery.detect_pg_major``
OFFLINE against the ``fake_supabase_repo`` factory (conftest) — no docker, no DB.

The two fleet layouts (RESEARCH Pitfall 1 / D-08-13):
  * canonical ``supabase/migrations/*.sql``  (repo uses this)
  * legacy-layout ``packages/api-client/sql/00N_*.sql`` (common in older Supabase repos)

Discovery MUST: prefer the canonical layout when both exist, exclude
``node_modules``, sort numerically, record the matched layout, and emit an
honest ``layout="none"`` sentinel (never a silent no-op) when nothing is found.
``detect_pg_major`` parses ``supabase/config.toml [db].major_version`` with a
faithful default of 15 (D-08-09).
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.supabase.discovery import (
    MigrationSet,
    detect_pg_major,
    find_migrations,
)


def test_canonical_layout_numeric_order(tmp_path, fake_supabase_repo):
    """supabase/migrations/0001..0002 → numeric order, layout recorded."""
    repo = fake_supabase_repo(tmp_path, api_client_layout=False)
    result = find_migrations(repo)
    assert isinstance(result, MigrationSet)
    assert result.layout == "supabase/migrations"
    names = [p.name for p in result.files]
    assert names == ["0001_init.sql", "0002_policies.sql"]


def test_legacy_numbered_sql_layout(tmp_path, fake_supabase_repo):
    """legacy-layout packages/api-client/sql/001..002 found when no canonical dir."""
    repo = fake_supabase_repo(tmp_path, supabase_layout=False)
    result = find_migrations(repo)
    assert result.layout == "legacy-numbered-sql"
    names = [p.name for p in result.files]
    assert names == ["001_schema.sql", "002_functions.sql"]


def test_canonical_wins_when_both_present(tmp_path, fake_supabase_repo):
    """Both layouts present → canonical wins, legacy globs ignored (D-08-13)."""
    repo = fake_supabase_repo(tmp_path)  # writes BOTH layouts
    result = find_migrations(repo)
    assert result.layout == "supabase/migrations"
    # Only the canonical files, never the legacy api-client ones.
    assert all("api-client" not in str(p) for p in result.files)
    assert [p.name for p in result.files] == ["0001_init.sql", "0002_policies.sql"]


def test_node_modules_sql_excluded(tmp_path, fake_supabase_repo):
    """A node_modules/**/sql/001_*.sql is NEVER returned by the legacy glob."""
    repo = fake_supabase_repo(tmp_path, supabase_layout=False)
    nm = repo / "node_modules" / "some-dep" / "sql"
    nm.mkdir(parents=True)
    (nm / "001_vendored.sql").write_text("select 1;\n", encoding="utf-8")
    result = find_migrations(repo)
    assert result.layout == "legacy-numbered-sql"
    assert all("node_modules" not in p.parts for p in result.files)
    assert all(p.name != "001_vendored.sql" for p in result.files)


def test_zero_migrations_returns_none_sentinel(tmp_path, fake_supabase_repo):
    """No migrations anywhere → empty files + layout='none' (honest sentinel)."""
    repo = fake_supabase_repo(
        tmp_path, supabase_layout=False, api_client_layout=False
    )
    result = find_migrations(repo)
    assert result.files == []
    assert result.layout == "none"


def test_detect_pg_major_from_config(tmp_path, fake_supabase_repo):
    """[db].major_version = 15 in config.toml → 15."""
    repo = fake_supabase_repo(tmp_path)  # config_toml writes major_version = 15
    assert detect_pg_major(repo) == 15


def test_detect_pg_major_default_when_config_absent(tmp_path, fake_supabase_repo):
    """No config.toml → default 15 (D-08-09), never a crash."""
    repo = fake_supabase_repo(tmp_path, config_toml=False)
    assert detect_pg_major(repo) == 15


def test_detect_pg_major_reads_real_value(tmp_path):
    """A config with major_version = 17 → 17 (the example app's real value)."""
    sup = tmp_path / "supabase"
    sup.mkdir()
    (sup / "config.toml").write_text("[db]\nmajor_version = 17\n", encoding="utf-8")
    assert detect_pg_major(tmp_path) == 17


def test_detect_pg_major_default_when_key_absent(tmp_path):
    """config.toml present but no [db].major_version → default 15."""
    sup = tmp_path / "supabase"
    sup.mkdir()
    (sup / "config.toml").write_text("[api]\nport = 54321\n", encoding="utf-8")
    assert detect_pg_major(tmp_path) == 15


def test_detect_pg_major_default_on_parse_error(tmp_path):
    """A malformed config.toml degrades to the default, never raises."""
    sup = tmp_path / "supabase"
    sup.mkdir()
    (sup / "config.toml").write_text("this is not = valid = toml [[[", encoding="utf-8")
    assert detect_pg_major(tmp_path) == 15
