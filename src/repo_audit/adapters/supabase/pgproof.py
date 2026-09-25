"""Ephemeral ``supabase/postgres`` lifecycle + the RLS-01 floor entry (Plan 08-02).

This module owns the heaviest infra in Phase 08: standing up a throwaway,
**Supabase-faithful** Postgres, applying the repo's migrations in order, and
linting the live catalog with splinter. It refuses to ship lints from a
wrong/stock server (D-08-10) — faithfulness over convenience.

Why the ``supabase/postgres`` image. Typical Supabase
SQL references ``auth.users``, ``auth.uid()``, the ``service_role`` role, etc.
A stock ``postgres:N`` image makes BOTH the migration-apply AND splinter FAIL
(``schema "auth" does not exist``). The ``supabase/postgres`` image ships the
real ``auth`` schema/roles/functions, so it is the ONLY faithful base. If docker
is down or the pinned image is unpullable we degrade to ``unavailable`` with a
clear reason — NEVER a stock-postgres fallback (that would ship a misleading
partial).

Image pinning (D-08-09 / FND-03 reproducibility). Images are pinned BY DIGEST
(``tag@sha256:…``), selected by the PG major from ``supabase/config.toml``. The
digest provenance is recorded in a greppable comment beside each entry.

Migration apply (D-08-15). Each discovered file is applied via
``psql <dsn> -v ON_ERROR_STOP=1 -1 -f <file>`` through the shared ``run_tool``
seam (shell=False, list[str] argv — no shell interpolation of repo paths,
T-08-08). The FIRST file that fails to apply raises :class:`MigrationApplyFailed`
and degrades the WHOLE RLS-01 dimension to ``unavailable`` — never a partial
lint over a half-applied schema.

Teardown (D-08-08, Pitfall 5). The ``with DockerContainer(...)`` block + the
testcontainers Ryuk reaper guarantee the container is removed even on a crash
mid-apply. Temp/working files (none are written today) would live in the scan
tempdir OUTSIDE the target repo (SC-5 read-only contract).

Why the generic ``DockerContainer`` (not ``PostgresContainer``). testcontainers'
``PostgresContainer`` injects ``POSTGRES_USER=test``/``POSTGRES_PASSWORD=test``
and probes readiness with ``psql --username test`` over a local socket — but the
``supabase/postgres`` image's post-init step runs as a local role that trips
``peer`` auth for a non-``postgres`` user and the container EXITS (verified
2026-06-02: ``no match in usermap "supabase_map"`` → ``FATAL: Peer
authentication failed``). The faithful recipe is: keep the default ``postgres``
superuser, set ``POSTGRES_PASSWORD=postgres``, and wait for the image's own
docker HEALTHCHECK to report ``healthy`` before connecting over TCP — the image
restarts its server once during init, so a too-early TCP probe is dropped. We
therefore drive a generic ``DockerContainer`` and own the wait + DSN build.

``collect_rls_static`` is the never-raising floor entry (the base.py contract):
every failure mode — no migrations, docker absent, image unpullable, apply
failure — is caught and folded into ``AdapterResult(status="unavailable")``.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.supabase.discovery import (
    detect_pg_major,
    find_migrations,
)
from repo_audit.adapters.supabase.splinter_collect import (
    map_splinter_rows,
    run_splinter,
)
from repo_audit.adapters.supabase.splinter_fetch import SplinterSqlUnavailable
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

# Pinned supabase/postgres images BY DIGEST (D-08-09 / FND-03). Selected by PG
# major from supabase/config.toml. Digests resolved from Docker Hub via
# `docker manifest inspect --verbose supabase/postgres:<tag>` on 2026-06-02
# (the manifest-list / multi-arch image index digest, so the correct per-arch
# image is selected at pull time). Tags verified present via the Docker Hub API
# (2026-05-30): 15.14.1.132 / 17.6.1.132.
#
#   supabase/postgres:15.14.1.132 → sha256:e32852813b7b740c187f45fd0a482eb0700b22b248e49e2adc3fe54e9785581f
#   supabase/postgres:17.6.1.132  → sha256:9d50688a826cf1455a0e91013160171de73b4d31df1509014e73463fb276a84d
SUPABASE_PG_IMAGES: dict[int, str] = {
    15: (
        "supabase/postgres:15.14.1.132@sha256:"
        "e32852813b7b740c187f45fd0a482eb0700b22b248e49e2adc3fe54e9785581f"
    ),
    17: (
        "supabase/postgres:17.6.1.132@sha256:"
        "9d50688a826cf1455a0e91013160171de73b4d31df1509014e73463fb276a84d"
    ),
}

# Default major when config.toml selects an unmapped one — fall back to the
# nearest mapped image we ship (15 is the conservative floor; D-08-09 default).
_FALLBACK_MAJOR: int = 15

# Faithful-boot credentials for the supabase/postgres image (see module
# docstring). We connect as `supabase_admin` — the image's TRUE superuser and
# the OWNER of the platform schemas (`storage`, `auth`, …). The default
# `postgres` role in this image is NOT a superuser and cannot create objects in
# the `storage` schema (owned by `supabase_admin`), which the storage prelude +
# fleet migrations require (verified 2026-06-02: `permission denied for schema
# storage`). `POSTGRES_PASSWORD` sets the password used for every role over TCP.
_PG_SUPERUSER: str = "supabase_admin"
_PG_PASSWORD: str = "postgres"
_PG_DBNAME: str = "postgres"
_PG_INTERNAL_PORT: int = 5432


class EphemeralPgUnavailable(Exception):
    """Docker/image could not provide a faithful ephemeral DB.

    Raised when the pinned image cannot be selected/pulled or the container
    cannot be started. Mapped upstream to ``AdapterResult(status="unavailable")``
    — NEVER a stock-postgres fallback (D-08-10).
    """


class MigrationApplyFailed(Exception):
    """A discovered migration failed to apply via psql (D-08-15).

    Carries the failing file and an stderr tail. Degrades the WHOLE RLS-01
    dimension to ``unavailable`` — never a partial lint over a half-applied
    schema.
    """

    def __init__(self, file: Path, stderr_tail: str) -> None:
        self.file = file
        self.stderr_tail = stderr_tail
        super().__init__(
            f"migration apply failed: {file.name}: {stderr_tail.strip()[:500]}"
        )


def _select_image(pg_major: int) -> str:
    """Pick the pinned image for ``pg_major`` (fallback to the mapped floor)."""
    image = SUPABASE_PG_IMAGES.get(pg_major)
    if image is None:
        image = SUPABASE_PG_IMAGES.get(_FALLBACK_MAJOR)
    if image is None:  # defensive: the table is never empty in practice
        raise EphemeralPgUnavailable(
            f"no pinned supabase/postgres image for PG major {pg_major}"
        )
    return image


def _build_dsn(host: str, port: int) -> str:
    """Build a bare ``postgresql://`` DSN psql + psycopg3 both accept."""
    return (
        f"postgresql://{_PG_SUPERUSER}:{_PG_PASSWORD}@{host}:{port}/{_PG_DBNAME}"
    )


def _wait_healthy_then_ready(container, dsn: str, timeout_seconds: float) -> None:
    """Wait for the image HEALTHCHECK, then confirm a real psycopg3 connect.

    The ``supabase/postgres`` image restarts its server once during init, so a
    bare TCP probe can be dropped mid-init. We first wait for the container's
    own docker ``health`` to report ``healthy`` (the image ships a pg-isready
    healthcheck), then do ONE authoritative psycopg3 connect to be certain the
    server accepts our credentials over TCP before applying migrations.
    """
    import psycopg

    wrapped = container.get_wrapped_container()
    deadline = time.perf_counter() + timeout_seconds
    last_err: Exception | None = None

    while time.perf_counter() < deadline:
        try:
            wrapped.reload()
            state = wrapped.attrs.get("State", {})
            if state.get("Status") == "exited":
                raise EphemeralPgUnavailable(
                    "supabase/postgres container exited during init "
                    "(image did not boot cleanly)"
                )
            health = (state.get("Health") or {}).get("Status")
        except EphemeralPgUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — docker API hiccup; retry
            last_err = exc
            time.sleep(1.0)
            continue

        # No healthcheck on the image → fall back to a direct connect probe.
        if health in (None, "healthy"):
            try:
                with psycopg.connect(dsn, connect_timeout=3):
                    return
            except Exception as exc:  # noqa: BLE001 — server still settling
                last_err = exc
        time.sleep(1.0)

    raise EphemeralPgUnavailable(
        f"ephemeral DB not ready within {timeout_seconds}s: {last_err}"
    )


def _apply_migration(
    dsn: str,
    file: Path,
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_seconds: float,
) -> None:
    """Apply one migration via ``psql … -v ON_ERROR_STOP=1 -1 -f <file>``.

    The path is passed as a discrete ``-f <path>`` argv entry through
    ``run_tool`` (shell=False) — no shell interpolation of repo-controlled paths
    (T-08-08). Any non-zero / sentinel returncode raises
    :class:`MigrationApplyFailed`.
    """
    result = run_tool(
        ["psql", dsn, "-v", "ON_ERROR_STOP=1", "-1", "-f", str(file)],
        env=env,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )
    if result.returncode == EXEC_FAILED:
        # psql binary missing → cannot apply faithfully → unavailable upstream.
        raise EphemeralPgUnavailable(
            f"psql not available to apply migrations: {result.stderr.strip()[:300]}"
        )
    if result.returncode == TIMED_OUT:
        raise MigrationApplyFailed(file, f"timed out: {result.stderr}")
    if result.returncode != 0:
        raise MigrationApplyFailed(file, result.stderr or result.stdout)


# Minimal Supabase `storage` prelude (D-08-08 _seed_supabase_prelude_if_needed,
# RESEARCH Pattern 1). The base `supabase/postgres` image ships the `auth`
# schema/roles/functions but NOT the `storage` SERVICE tables
# (`storage.buckets`, `storage.objects`) or `storage.foldername()` — those are
# created by the storage-api service migrations in a full Supabase stack, not by
# the bare DB image (verified 2026-06-02). Real-world Supabase repos reference
# them in their migrations + RLS policies, so without this prelude the apply
# fails on `relation "storage.buckets" does not exist`. We seed ONLY objects the
# image lacks, idempotently (CREATE … IF NOT EXISTS), faithful to Supabase's
# real storage schema shape so splinter introspects a realistic catalog. This is
# a SEED of missing platform objects, NEVER a fabrication of the repo's own
# schema — repo migrations still own every app table/policy.
_STORAGE_PRELUDE_SQL: str = """
create schema if not exists storage;

create table if not exists storage.buckets (
    id text primary key,
    name text not null,
    owner uuid,
    created_at timestamptz default now(),
    updated_at timestamptz default now(),
    public boolean default false,
    avif_autodetection boolean default false,
    file_size_limit bigint,
    allowed_mime_types text[]
);

create table if not exists storage.objects (
    id uuid primary key default gen_random_uuid(),
    bucket_id text references storage.buckets(id),
    name text,
    owner uuid,
    created_at timestamptz default now(),
    updated_at timestamptz default now(),
    last_accessed_at timestamptz default now(),
    metadata jsonb,
    path_tokens text[] generated always as (string_to_array(name, '/')) stored
);

alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;

create or replace function storage.foldername(name text)
returns text[]
language plpgsql
stable
as $func$
declare
    parts text[];
begin
    parts := string_to_array(name, '/');
    return parts[1 : array_length(parts, 1) - 1];
end
$func$;
"""


def _seed_storage_prelude(dsn: str, timeout_seconds: float) -> None:
    """Seed the minimal `storage` schema the base image lacks (idempotent).

    Runs the :data:`_STORAGE_PRELUDE_SQL` via psycopg3. ``CREATE … IF NOT
    EXISTS`` / ``CREATE OR REPLACE`` make it a no-op when a fuller image already
    ships these objects. Raises :class:`EphemeralPgUnavailable` on failure — a
    prelude that cannot seed means the ephemeral DB is not faithful enough to
    apply fleet migrations, which is an infrastructure unavailability, not a
    repo finding.
    """
    import psycopg

    try:
        with psycopg.connect(dsn, connect_timeout=int(max(1, timeout_seconds))) as conn:
            with conn.cursor() as cur:
                cur.execute(_STORAGE_PRELUDE_SQL)
            conn.commit()
    except Exception as exc:  # noqa: BLE001 — seeding failure → infra unavailable
        raise EphemeralPgUnavailable(
            f"could not seed the storage prelude: {exc}"
        ) from exc


@contextmanager
def ephemeral_supabase_pg(
    migrations: list[Path],
    *,
    pg_major: int,
    env: dict[str, str],
    cwd: Path,
    timeout_seconds: float,
) -> Iterator[str]:
    """Stand up the pinned image, apply ``migrations`` in order, yield the DSN.

    Lifecycle (guaranteed-teardown):
      1. Select the pinned image by ``pg_major`` (unmapped → fallback floor).
      2. ``with DockerContainer(image)`` configured with the faithful
         ``postgres`` superuser + ``POSTGRES_PASSWORD`` and the internal 5432
         exposed — Ryuk-backed teardown even on a crash mid-apply.
      3. Wait for the image HEALTHCHECK to report ``healthy``, then ONE
         authoritative psycopg3 connect over TCP (the image restarts once
         during init).
      3b. Seed the minimal ``storage`` platform schema the base image omits
         (idempotent; the image ships ``auth`` but not the storage-service
         tables fleet migrations reference).
      4. Apply each migration in order via psql/``run_tool`` with
         ``ON_ERROR_STOP=1``; the first failure raises
         :class:`MigrationApplyFailed`.
      5. ``yield dsn``.

    Raises:
        EphemeralPgUnavailable: docker down / image unpullable / not ready /
            psql missing.
        MigrationApplyFailed: a migration failed to apply (whole-dimension
            unavailable upstream).
    """
    from testcontainers.core.container import DockerContainer

    image = _select_image(pg_major)

    try:
        # ONLY set POSTGRES_PASSWORD. The image already ships the `postgres`
        # superuser + `postgres` db; explicitly setting POSTGRES_USER /
        # POSTGRES_DB activates the image's `migrate.sh` init path which expects
        # a `supabase_admin` role and EXITS the container with `role
        # "supabase_admin" does not exist` (verified 2026-06-02). Setting only
        # the password keeps the default faithful boot.
        container = (
            DockerContainer(image)
            .with_env("POSTGRES_PASSWORD", _PG_PASSWORD)
            .with_exposed_ports(_PG_INTERNAL_PORT)
        )
    except Exception as exc:  # noqa: BLE001 — construction-time docker/image fault
        raise EphemeralPgUnavailable(
            f"could not construct supabase/postgres container ({image}): {exc}"
        ) from exc

    try:
        with container as pg:
            host = pg.get_container_host_ip()
            port = int(pg.get_exposed_port(_PG_INTERNAL_PORT))
            dsn = _build_dsn(host, port)
            _wait_healthy_then_ready(pg, dsn, timeout_seconds)
            # Seed the minimal `storage` platform schema the base image omits
            # (the image ships `auth` but not the storage-service tables) so
            # fleet migrations that reference storage.buckets/objects apply.
            _seed_storage_prelude(dsn, timeout_seconds)
            for file in migrations:
                _apply_migration(
                    dsn,
                    file,
                    env=env,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                )
            yield dsn
        # Context exit + Ryuk reaper guarantee the container is removed here,
        # including on exceptions raised inside the `with` body above.
    except (EphemeralPgUnavailable, MigrationApplyFailed):
        raise
    except Exception as exc:  # noqa: BLE001 — docker daemon down / pull failure
        raise EphemeralPgUnavailable(
            f"ephemeral supabase/postgres lifecycle failed ({image}): {exc}"
        ) from exc


def collect_rls_static(
    repo: Path,
    *,
    env: dict[str, str] | None = None,
    timeout_seconds: float = 600.0,
) -> AdapterResult:
    """The RLS-01 floor entry — NEVER raises (base.py contract).

    Discovers migrations, stands up the faithful pinned image, applies them in
    order, runs splinter, and maps the rows to verify-phrased static findings.
    Every failure mode degrades to ``AdapterResult(status="unavailable")`` with
    a clear reason — and NEVER falls back to stock postgres (D-08-10).

    Args:
        repo: the target repository root.
        env: optional pre-built cache-redirected env (defaults to a fresh
            per-scan env inside a tempdir OUTSIDE the repo, SC-5).
        timeout_seconds: overall wall-clock bound for readiness + each apply.

    Returns:
        ``AdapterResult`` — ``status="ok"`` with findings on success; otherwise
        ``status="unavailable"`` with the reason in ``notes``.
    """
    base_kwargs = dict(
        source_adapter="supabase",
        source_tool="splinter",
        dimension="security",
    )

    try:
        mig = find_migrations(repo)
    except Exception as exc:  # noqa: BLE001 — discovery must never crash the floor
        return AdapterResult(
            status="unavailable",
            notes=f"migration discovery failed: {exc}",
            **base_kwargs,
        )

    if mig.layout == "none":
        return AdapterResult(
            status="unavailable",
            notes="no migrations found (searched supabase/migrations and **/sql/00N_*.sql)",
            **base_kwargs,
        )

    pg_major = detect_pg_major(repo)

    try:
        with scan_tempdir() as tempdir:
            scan_env = env if env is not None else build_scan_env(tempdir)
            with ephemeral_supabase_pg(
                mig.files,
                pg_major=pg_major,
                env=scan_env,
                cwd=tempdir,
                timeout_seconds=timeout_seconds,
            ) as dsn:
                rows = run_splinter(dsn, timeout_seconds=timeout_seconds)
                findings = map_splinter_rows(rows)
        return AdapterResult(
            findings=findings,
            status="ok",
            notes=f"layout={mig.layout}; pg_major={pg_major}; splinter_rows={len(findings)}",
            **base_kwargs,
        )
    except MigrationApplyFailed as exc:
        return AdapterResult(
            status="unavailable",
            notes=(
                f"migration apply failed on {exc.file.name}; RLS-01 dimension "
                f"degraded (never a partial lint over a half-applied schema): "
                f"{exc.stderr_tail.strip()[:300]}"
            ),
            **base_kwargs,
        )
    except EphemeralPgUnavailable as exc:
        return AdapterResult(
            status="unavailable",
            notes=(
                f"ephemeral supabase/postgres unavailable (docker down / image "
                f"unpullable / not ready); no stock-postgres fallback (D-08-10): {exc}"
            ),
            **base_kwargs,
        )
    except SplinterSqlUnavailable as exc:
        return AdapterResult(status="unavailable", notes=str(exc), **base_kwargs)
    except Exception as exc:  # noqa: BLE001 — absolute never-raise backstop
        return AdapterResult(
            status="unavailable",
            notes=f"RLS-01 static floor failed unexpectedly: {type(exc).__name__}: {exc}",
            **base_kwargs,
        )


__all__ = [
    "SUPABASE_PG_IMAGES",
    "EphemeralPgUnavailable",
    "MigrationApplyFailed",
    "collect_rls_static",
    "ephemeral_supabase_pg",
]
