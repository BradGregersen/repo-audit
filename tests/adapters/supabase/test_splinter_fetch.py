"""splinter.sql first-use fetch: pinned commit, pinned sha256, user cache.

supabase/splinter publishes no license, so repo-audit does not redistribute its
lint set. It is downloaded on first use from a commit-pinned URL, checked
against a pinned sha256, and cached under the user cache dir.

All offline. An autouse fixture makes the single network seam
(``splinter_fetch._open_url``) raise, so a test that forgets to stub it fails
loudly instead of reaching the network. The real upstream bytes are not
available offline, so each test pins ``SPLINTER_SHA256`` to the hash of a
small fake payload.
"""
from __future__ import annotations

import hashlib
import re
import urllib.error
from pathlib import Path

import pytest

import repo_audit
from repo_audit.adapters.supabase import provenance as prov_mod
from repo_audit.adapters.supabase import splinter_collect, splinter_fetch
from repo_audit.adapters.supabase.splinter_fetch import SplinterSqlUnavailable

PAYLOAD = b"set local search_path = '';\nselect 1;\n"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail any test that reaches the network seam without stubbing it."""

    def _refuse(url, timeout):
        raise AssertionError("network touched in a unit test")

    monkeypatch.setattr(splinter_fetch, "_open_url", _refuse)


@pytest.fixture
def cache_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "cache-home"
    monkeypatch.setenv("XDG_CACHE_HOME", str(home))
    return home


@pytest.fixture
def pinned_to_payload(monkeypatch) -> str:
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    monkeypatch.setattr(splinter_fetch, "SPLINTER_SHA256", digest)
    return digest


def _stub_download(monkeypatch, body: bytes) -> list[str]:
    calls: list[str] = []

    def _fake(url, timeout):
        calls.append(url)
        return body

    monkeypatch.setattr(splinter_fetch, "_open_url", _fake)
    return calls


# --- constants ---------------------------------------------------------------


def test_constants_pin_commit_hash_and_url():
    assert re.fullmatch(r"[0-9a-f]{40}", splinter_fetch.SPLINTER_COMMIT)
    assert (
        splinter_fetch.SPLINTER_SHA256
        == "618a189a2d25c81e1d77efb24acca72c9c832aeac9680ba06a1ba5ec666b2d3d"
    )
    assert splinter_fetch.SPLINTER_URL.startswith(
        "https://raw.githubusercontent.com/supabase/splinter/"
    )
    assert splinter_fetch.SPLINTER_COMMIT in splinter_fetch.SPLINTER_URL


def test_no_vendored_copy_ships_in_the_package():
    vendored = Path(repo_audit.__file__).parent / "vendor" / "splinter"
    assert not vendored.exists()


# --- cache path ---------------------------------------------------------------


def test_cache_path_honours_xdg_cache_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert splinter_fetch.splinter_cache_path() == (
        tmp_path / "xdg" / "repo-audit" / "splinter" / "splinter.sql"
    )


def test_cache_path_falls_back_to_home_dot_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert splinter_fetch.splinter_cache_path() == (
        tmp_path / "home" / ".cache" / "repo-audit" / "splinter" / "splinter.sql"
    )


# --- ensure / load --------------------------------------------------------------


def test_cache_hit_uses_no_network(cache_home, pinned_to_payload):
    path = splinter_fetch.splinter_cache_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(PAYLOAD)

    # The autouse fixture still refuses the network; a hit must not call it.
    assert splinter_fetch.ensure_splinter_sql() == path
    assert splinter_fetch.load_splinter_sql() == PAYLOAD.decode("utf-8")


def test_cache_miss_downloads_verifies_and_caches(
    cache_home, pinned_to_payload, monkeypatch
):
    calls = _stub_download(monkeypatch, PAYLOAD)

    path = splinter_fetch.ensure_splinter_sql()

    assert calls == [splinter_fetch.SPLINTER_URL]
    assert path == splinter_fetch.splinter_cache_path()
    assert path.read_bytes() == PAYLOAD
    # The atomic write leaves nothing else behind in the cache dir.
    assert sorted(p.name for p in path.parent.iterdir()) == ["splinter.sql"]


def test_hash_mismatch_raises_and_caches_nothing(
    cache_home, pinned_to_payload, monkeypatch
):
    _stub_download(monkeypatch, b"select 'tampered';\n")
    path = splinter_fetch.splinter_cache_path()

    with pytest.raises(SplinterSqlUnavailable) as info:
        splinter_fetch.ensure_splinter_sql()

    message = str(info.value)
    assert splinter_fetch.SPLINTER_URL in message
    assert str(path) in message
    assert not path.exists()
    if path.parent.exists():
        assert list(path.parent.iterdir()) == []


def test_offline_raises_naming_url_and_cache_path(
    cache_home, pinned_to_payload, monkeypatch
):
    def _offline(url, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(splinter_fetch, "_open_url", _offline)
    path = splinter_fetch.splinter_cache_path()

    with pytest.raises(SplinterSqlUnavailable) as info:
        splinter_fetch.load_splinter_sql()

    message = str(info.value)
    assert splinter_fetch.SPLINTER_URL in message
    assert str(path) in message
    assert not path.exists()


def test_corrupt_cache_is_replaced(cache_home, pinned_to_payload, monkeypatch):
    path = splinter_fetch.splinter_cache_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not the lint set\n")
    calls = _stub_download(monkeypatch, PAYLOAD)

    assert splinter_fetch.ensure_splinter_sql() == path
    assert calls == [splinter_fetch.SPLINTER_URL]
    assert path.read_bytes() == PAYLOAD


# --- consumers -------------------------------------------------------------------


def test_run_splinter_propagates_unavailable_before_connecting(monkeypatch):
    def _unavailable(**_kwargs):
        raise SplinterSqlUnavailable("splinter.sql unavailable: test")

    def _no_connect(*_a, **_k):
        raise AssertionError("psycopg.connect must not be reached")

    import psycopg

    monkeypatch.setattr(splinter_collect, "load_splinter_sql", _unavailable)
    monkeypatch.setattr(psycopg, "connect", _no_connect)

    with pytest.raises(SplinterSqlUnavailable):
        splinter_collect.run_splinter("postgresql://u:p@127.0.0.1:5432/db")


def test_read_splinter_sha_returns_the_pinned_commit():
    assert prov_mod.read_splinter_sha() == splinter_fetch.SPLINTER_COMMIT
