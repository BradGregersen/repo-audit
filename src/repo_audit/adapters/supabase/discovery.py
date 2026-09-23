"""Dual-layout migration discovery + config.toml PG-major parse (Plan 08-02).

The RLS-01 floor must apply a repo's SQL migrations against an ephemeral
``supabase/postgres`` before linting. Two fleet layouts exist (RESEARCH
Pitfall 1 / D-08-13):

  * **canonical** — ``supabase/migrations/*.sql`` (the standard ``supabase db``
    layout; ``repo`` uses this).
  * **legacy-numbered-sql** — a numbered ``sql/00N_*.sql`` directory elsewhere
    in the tree (repos that predate ``supabase db`` migration management keep
    numbered SQL under an ``**/sql/`` dir).

:func:`find_migrations` searches the canonical layout FIRST; only if it is empty
does it fall back to the numbered ``**/sql/`` glob (``node_modules`` excluded).
The matched layout is RECORDED on the returned :class:`MigrationSet` so Plan 05
can disclose it in the scope ledger — and a ``layout="none"`` sentinel is the
honest "no migrations found" signal (never a silent no-op).

:func:`detect_pg_major` reads ``supabase/config.toml [db].major_version`` with
``tomllib`` (read-only stdlib) so :mod:`pgproof` can select the matching pinned
image tag. Missing file / missing key / parse error all degrade to the faithful
default of 15 (D-08-09). Both functions resolve at CALL time — no module-load
caching (the Phase 3 lesson).
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# D-08-09: the faithful default PG major when config.toml is absent / silent.
DEFAULT_PG_MAJOR: int = 15

# The two fleet layouts plus the honest "nothing found" sentinel.
MigrationLayout = Literal["supabase/migrations", "legacy-numbered-sql", "none"]


class MigrationSet(BaseModel):
    """Ordered migrations + the layout they were discovered under.

    ``extra='forbid'`` (D-03): a typo at construction raises ``ValidationError``
    before the object exists. ``layout`` is the string Plan 05 records in the
    scope ledger; ``layout == "none"`` is the honest-unavailable sentinel that
    drives ``collect_rls_static`` to emit ``unavailable: no migrations found``.
    """

    model_config = ConfigDict(extra="forbid")

    files: list[Path] = Field(default_factory=list)
    layout: MigrationLayout = "none"


def find_migrations(repo: Path) -> MigrationSet:
    """Discover migrations across BOTH fleet layouts, canonical-first.

    Logic:
      1. ``canonical = sorted((repo/"supabase"/"migrations").glob("*.sql"))``.
         If non-empty → ``layout="supabase/migrations"`` (canonical WINS even
         when a legacy layout also exists, D-08-13).
      2. Else ``legacy = [p for p in repo.glob("**/sql/[0-9][0-9][0-9]_*.sql")
         if "node_modules" not in p.parts]`` sorted by ``p.name`` →
         ``layout="legacy-numbered-sql"``.
      3. Else ``files=[]``, ``layout="none"`` (honest sentinel).

    Args:
        repo: the target repository root.

    Returns:
        A :class:`MigrationSet` with the ordered files and the matched layout.
    """
    repo = Path(repo)

    canonical = sorted((repo / "supabase" / "migrations").glob("*.sql"))
    if canonical:
        return MigrationSet(files=canonical, layout="supabase/migrations")

    legacy = [
        p
        for p in repo.glob("**/sql/[0-9][0-9][0-9]_*.sql")
        if "node_modules" not in p.parts
    ]
    if legacy:
        legacy = sorted(legacy, key=lambda p: p.name)
        return MigrationSet(files=legacy, layout="legacy-numbered-sql")

    return MigrationSet(files=[], layout="none")


def detect_pg_major(repo: Path) -> int:
    """Read ``supabase/config.toml [db].major_version``; default 15 (D-08-09).

    Read-only ``tomllib`` parse. Missing file, missing ``[db]`` table, missing
    ``major_version`` key, or any parse/type error all degrade to
    :data:`DEFAULT_PG_MAJOR` — this never raises (the image-selection caller
    must always get an int). Resolved at CALL time (no module-load caching).

    Args:
        repo: the target repository root.

    Returns:
        The configured PG major as an ``int``, or 15 by default.
    """
    config_path = Path(repo) / "supabase" / "config.toml"
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return DEFAULT_PG_MAJOR

    db_section = data.get("db")
    if not isinstance(db_section, dict):
        return DEFAULT_PG_MAJOR
    major = db_section.get("major_version")
    if isinstance(major, int) and not isinstance(major, bool):
        return major
    return DEFAULT_PG_MAJOR


__all__ = [
    "DEFAULT_PG_MAJOR",
    "MigrationLayout",
    "MigrationSet",
    "detect_pg_major",
    "find_migrations",
]
