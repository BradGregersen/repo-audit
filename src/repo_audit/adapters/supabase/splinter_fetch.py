"""Fetch splinter.sql on first use: pinned commit, pinned sha256, user cache.

The Supabase static RLS floor runs the lint set from supabase/splinter. That
repository publishes no license, so repo-audit does not redistribute the file.
Instead it is downloaded once from a URL pinned to one upstream commit, checked
against a pinned sha256, and cached under the user cache dir
(``$XDG_CACHE_HOME/repo-audit/splinter/`` or ``~/.cache/repo-audit/splinter/``).
Later scans read the cache and make no network call.

Any failure (offline, HTTP error, oversized response, hash mismatch, unwritable
cache) raises :class:`SplinterSqlUnavailable`, whose message names the URL and
the cache path. Callers turn that into an ``unavailable`` floor. A download
that does not match the pinned hash is never written to the cache.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from pathlib import Path

SPLINTER_COMMIT: str = "a7f71080ed059de8a7f00addd71ade19b82a4108"
SPLINTER_SHA256: str = "618a189a2d25c81e1d77efb24acca72c9c832aeac9680ba06a1ba5ec666b2d3d"
SPLINTER_URL: str = (
    f"https://raw.githubusercontent.com/supabase/splinter/{SPLINTER_COMMIT}/splinter.sql"
)

# The upstream file is ~72 KB. Anything past 1 MiB is not the lint set.
_MAX_BYTES = 1024 * 1024


class SplinterSqlUnavailable(RuntimeError):
    """splinter.sql could not be loaded from the cache or fetched and verified."""


def splinter_cache_path() -> Path:
    """Return the cache location for splinter.sql (the directory is not created)."""
    cache_home = os.environ.get("XDG_CACHE_HOME")
    base = Path(cache_home) if cache_home else (Path.home() / ".cache")
    return base / "repo-audit" / "splinter" / "splinter.sql"


def _open_url(url: str, timeout: float) -> bytes:
    """Download ``url`` and return its body. The only network call in this module."""
    import urllib.request

    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — fixed https URL pinned to a commit
        body = resp.read(_MAX_BYTES + 1)
    if len(body) > _MAX_BYTES:
        raise ValueError(f"response larger than {_MAX_BYTES} bytes")
    return body


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cached_ok(path: Path, expected: str) -> bool:
    try:
        return _sha256(path.read_bytes()) == expected
    except OSError:
        return False


def ensure_splinter_sql(*, timeout_seconds: float = 30.0) -> Path:
    """Return the path of a verified splinter.sql, downloading it if needed.

    A cached file whose sha256 matches the pin is returned with no network
    call. A missing or non-matching cache file is replaced by a fresh download,
    which is verified before it is written (atomically) to the cache.

    Raises:
        SplinterSqlUnavailable: the file could not be fetched, verified, or
            cached. The message names the URL and the cache path.
    """
    # Read the pins at call time so tests can monkeypatch them.
    expected = SPLINTER_SHA256
    url = SPLINTER_URL
    path = splinter_cache_path()

    if _cached_ok(path, expected):
        return path

    try:
        body = _open_url(url, timeout_seconds)
    except Exception as exc:  # noqa: BLE001 — every fetch failure is "unavailable"
        raise SplinterSqlUnavailable(
            f"splinter.sql unavailable: could not fetch {url} into {path}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if _sha256(body) != expected:
        raise SplinterSqlUnavailable(
            f"splinter.sql unavailable: download from {url} did not match the "
            f"pinned sha256 {expected}; nothing cached at {path}"
        )

    tmp_name: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=path.parent, prefix=".splinter-", suffix=".tmp"
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
        os.replace(tmp_name, path)
        tmp_name = None
    except Exception as exc:  # noqa: BLE001 — an unwritable cache is "unavailable"
        raise SplinterSqlUnavailable(
            f"splinter.sql unavailable: could not fetch {url} into {path}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    finally:
        if tmp_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)

    return path


def load_splinter_sql(*, timeout_seconds: float = 30.0) -> str:
    """Return the verified splinter.sql text (see :func:`ensure_splinter_sql`)."""
    return ensure_splinter_sql(timeout_seconds=timeout_seconds).read_text(
        encoding="utf-8"
    )


__all__ = [
    "SPLINTER_COMMIT",
    "SPLINTER_SHA256",
    "SPLINTER_URL",
    "SplinterSqlUnavailable",
    "ensure_splinter_sql",
    "load_splinter_sql",
    "splinter_cache_path",
]
