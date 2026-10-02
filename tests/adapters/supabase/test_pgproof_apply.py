"""How the ephemeral database applies a repo's migrations.

Supabase applies a project's migrations as ``postgres`` (SQL editor and CLI
alike), not as the image superuser ``supabase_admin``. Running them as
``supabase_admin`` changed which role's default privileges an un-qualified
``ALTER DEFAULT PRIVILEGES`` touched, so a real app's migration failed its own
post-condition here although it applies cleanly in production.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.supabase import pgproof
from repo_audit.adapters.supabase.pgproof import MigrationApplyFailed


def test_migrations_apply_as_postgres(monkeypatch, tmp_path):
    """Each migration runs after ``SET ROLE postgres``, inside the same single transaction."""
    captured = {}

    def _run(argv, *, env, cwd, timeout_seconds):
        captured["argv"] = list(argv)
        return InvocationResult(stdout="", stderr="", returncode=0, command=list(argv))

    monkeypatch.setattr(pgproof, "run_tool", _run)
    migration = tmp_path / "001_schema.sql"
    migration.write_text("select 1;\n", encoding="utf-8")

    pgproof._apply_migration(
        "postgresql://x", migration, env={}, cwd=tmp_path, timeout_seconds=5
    )

    argv = captured["argv"]
    assert "-1" in argv
    role = argv.index("SET ROLE postgres")
    assert argv[role - 1] == "-c"
    assert role < argv.index("-f")


def test_failure_message_keeps_the_error_line():
    """psql prints NOTICEs before the ERROR; the message must not cut the ERROR off."""
    stderr = (
        "psql:022.sql:369: NOTICE:  revoked authenticated EXECUTE on handle_new_user()\n"
        + "psql:022.sql:370: NOTICE:  " + "x" * 600 + "\n"
        + "psql:022.sql:519: ERROR:  ABORT: the postgres default-privileges row "
        "for schema storage still grants PUBLIC or anon EXECUTE on functions\n"
        + "CONTEXT:  PL/pgSQL function inline_code_block line 16 at RAISE\n"
    )

    err = MigrationApplyFailed(Path("022.sql"), stderr)

    assert "ERROR:  ABORT: the postgres default-privileges row" in str(err)
    assert "NOTICE" not in str(err)
    assert err.stderr_tail == stderr


def test_failure_message_without_an_error_line_keeps_the_text():
    """A failure with no ERROR line (a timeout, a crash) still reports what psql said."""
    err = MigrationApplyFailed(Path("001.sql"), "could not connect to server\n")

    assert "could not connect to server" in str(err)


def test_storage_prelude_mirrors_the_platform_grants():
    """``postgres`` must be able to use the storage tables, as on the platform."""
    sql = pgproof._STORAGE_PRELUDE_SQL

    assert "grant usage, create on schema storage to postgres" in sql
    assert "grant all on all tables in schema storage to postgres" in sql
    assert "grant supabase_storage_admin to postgres" in sql
