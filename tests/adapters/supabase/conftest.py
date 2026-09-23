"""Phase 08 supabase-adapter test fixtures (Plan 08-01, Task 3).

Mirrors the Phase 7 recorded-fixture discipline (tests/adapters/conftest.py
::recorded_tool_output + tests/adapters/sca/fixtures/PROVENANCE.md). Every
Wave 1 collector (Plans 02-04) unit-tests OFFLINE against the three frozen
fixtures loaded here — no docker, no node, no live DB.

Provided fixtures:
  * ``splinter_rows_fixture``  — the recorded 10-column splinter lint rows
    (Plan 02 row-mapper consumes these).
  * ``pgrls_sarif_fixture``    — the recorded pgrls ``--format sarif`` 2.1.0
    document (Plan 03 round-trips through the shared ``sarif_to_findings``).
  * ``squawk_json_fixture``    — the recorded ``squawk --reporter=json`` output
    over a destructive migration (Plan 03 native-JSON adapter).
  * ``fake_supabase_repo``     — factory writing BOTH discovery layouts on
    demand (``supabase/migrations/`` AND ``packages/api-client/sql/``) plus a
    minimal ``supabase/config.toml`` — for Plan 02's dual-layout discovery.
  * ``example_app_sql_dir``          — host-independent path to the example app's real SQL dir,
    ``pytest.skip`` when absent (Phase 3 host-independence lesson).

See ``fixtures/PROVENANCE.md`` for how each fixture was captured (live vs
doc-authored) + tool versions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

_FIXTURES = Path(__file__).parent / "fixtures"

# The example app has NO supabase/migrations/ — its SQL lives here (RESEARCH Pitfall 1,
# D-08-13). The two-account runtime script and the real lint corpus reference
# this path; it MUST stay host-independent via the skip below.
_EXAMPLE_APP_SQL_DIR = Path("/path/to/example-app/packages/api-client/sql")


def _load_json(name: str) -> Any:
    path = _FIXTURES / name
    if not path.exists():
        raise FileNotFoundError(f"supabase fixture missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# --- Recorded-fixture loaders ---------------------------------------------

@pytest.fixture
def splinter_rows_fixture() -> list[dict[str, Any]]:
    """Recorded splinter 10-column lint rows (Plan 02 row-mapper).

    Covers the level->Severity + categories->Dimension branches: an
    ERROR/SECURITY row (rls_disabled_in_public), a SECURITY user_metadata row
    (rls_references_user_metadata), an ERROR/SECURITY view row
    (security_definer_view), and a WARN/PERFORMANCE row (auth_rls_initplan).
    """
    return _load_json("splinter_rows.json")


@pytest.fixture
def pgrls_sarif_fixture() -> dict[str, Any]:
    """Recorded pgrls ``--format sarif`` 2.1.0 document (Plan 03).

    Round-trips through the shared ``sarif_to_findings`` with NO per-tool shim
    (A2). Carries rule ids + level + file/region locations.
    """
    return _load_json("pgrls.sarif.json")


@pytest.fixture
def squawk_json_fixture() -> list[dict[str, Any]]:
    """Recorded ``squawk --reporter=json`` output over a destructive migration.

    REAL captured output from squawk-cli 2.55.0 (ban-drop-column,
    require-concurrent-index-creation, prefer-robust-stmts, ...). Plan 03's
    native-JSON adapter maps these.
    """
    return _load_json("squawk.json")


# --- Dual-layout fake-repo factory ----------------------------------------

# Minimal Supabase-shaped SQL bodies for the discovery-layout fixtures. Kept
# tiny — discovery tests care about FILE LAYOUT, not SQL contents.
_MIGRATION_SQL = (
    "-- minimal migration\n"
    "create table public.tasks (id uuid primary key, owner_id uuid not null);\n"
    "alter table public.tasks enable row level security;\n"
    "create policy tasks_owner_only on public.tasks\n"
    "  using (owner_id = (select auth.uid()));\n"
)

# config.toml with a pinned PG major so Plan 02 can pick the matching
# supabase/postgres image tag.
_CONFIG_TOML = "[db]\nmajor_version = 15\n"


@pytest.fixture
def fake_supabase_repo() -> Callable[..., Path]:
    """Factory writing BOTH migration-discovery layouts into a tmp dir.

    Plan 02 must discover migrations under EITHER ``supabase/migrations/`` OR
    ``packages/api-client/sql/`` (older repos use the latter). This factory
    writes both on demand plus a minimal ``supabase/config.toml`` carrying
    ``[db] major_version = 15`` so the dual-layout discovery + PG-major
    selection paths can be exercised offline.

    Usage::

        def test_discovery(tmp_path, fake_supabase_repo):
            repo = fake_supabase_repo(tmp_path)
            assert (repo / "supabase" / "migrations" / "0001_init.sql").exists()
            assert (repo / "packages" / "api-client" / "sql" / "001_init.sql").exists()

    Args (to the returned callable):
        root: the directory to populate (typically ``tmp_path``).
        supabase_layout: write ``supabase/migrations/`` (default True).
        api_client_layout: write ``packages/api-client/sql/`` (default True).
        config_toml: write ``supabase/config.toml`` (default True).
    """

    def _build(
        root: Path,
        *,
        supabase_layout: bool = True,
        api_client_layout: bool = True,
        config_toml: bool = True,
    ) -> Path:
        root = Path(root)
        if supabase_layout:
            mig = root / "supabase" / "migrations"
            mig.mkdir(parents=True, exist_ok=True)
            (mig / "0001_init.sql").write_text(_MIGRATION_SQL, encoding="utf-8")
            (mig / "0002_policies.sql").write_text(_MIGRATION_SQL, encoding="utf-8")
        if config_toml:
            sup = root / "supabase"
            sup.mkdir(parents=True, exist_ok=True)
            (sup / "config.toml").write_text(_CONFIG_TOML, encoding="utf-8")
        if api_client_layout:
            sql = root / "packages" / "api-client" / "sql"
            sql.mkdir(parents=True, exist_ok=True)
            (sql / "001_schema.sql").write_text(_MIGRATION_SQL, encoding="utf-8")
            (sql / "002_functions.sql").write_text(_MIGRATION_SQL, encoding="utf-8")
        return root

    return _build


# --- Host-independent real-SQL path ---------------------------------------

@pytest.fixture
def example_app_sql_dir() -> Path:
    """Path to the example app's real SQL dir, or ``pytest.skip`` when absent.

    The Phase 3 host-independence lesson: any fixture that points at a real
    checkout under ``/path/to/repos`` must skip cleanly when that path is not
    present (CI / another machine), never fail.
    """
    if not _EXAMPLE_APP_SQL_DIR.is_dir():
        pytest.skip(f"example-app SQL dir not present at {_EXAMPLE_APP_SQL_DIR}")
    return _EXAMPLE_APP_SQL_DIR
