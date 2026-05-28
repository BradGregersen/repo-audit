"""D-46 cache-redirection env + per-scan tempdir context manager.

The three public symbols here are the structural guards behind SC-6
(post-scan ``git status --porcelain`` is empty). Every tool we shell
out to during a Phase 3 adapter run gets:

    * ``XDG_CACHE_HOME``    redirected to a per-scan tempdir, so tools
      that honour the XDG base-dir spec (eslint cache, some node deps)
      do not write to the user's ``~/.cache``.
    * ``npm_config_cache``  redirected to a per-scan tempdir, so any
      ``npm`` invocation (or tool that internally uses ``npm config``)
      does not write to the user's ``~/.npm``.
    * ``NO_COLOR=1``        suppresses ANSI escapes in subprocess
      stdout so recorded-fixture diffs stay clean.
    * ``CI=1``              switches many tools into
      non-interactive / no-progress-bar mode.

The parent ``os.environ`` is copied (so ``PATH``, ``HOME``, etc. still
work) and the four keys above are OVERRIDDEN. T-03-08 disposition:
``accept`` — the alternative (start from an empty env) breaks tools
that need ``PATH``/``HOME`` to function. A future ``--isolate-env``
flag (Phase 7) can offer the empty-env mode for paranoid users.

Public API (two interchangeable shapes — pick whichever reads cleanest
at the call site):

    * ``scan_cache_env(tempdir)`` — single context manager that yields
      the env dict, used by adapters that already own the tempdir
      (e.g. inside a ``scan_tempdir()`` block).

    * ``scan_tempdir()`` + ``build_scan_env(tempdir)`` — split into a
      tempdir context manager and a pure env-builder, used when an
      adapter needs to compose multiple env modifications on top.

Both shapes write the same four keys; they ARE NOT independent
implementations — ``scan_cache_env`` is built on top of the two pure
helpers below.
"""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def scan_tempdir() -> Iterator[Path]:
    """Yield a per-scan ``Path`` that auto-deletes on context exit.

    The prefix ``repo-audit-`` makes the tempdir easy to identify
    in ``/tmp`` listings if a debug session ever leaves one behind
    (cleanup is guaranteed by ``TemporaryDirectory`` under normal
    exit, including exception paths).
    """
    with tempfile.TemporaryDirectory(prefix="repo-audit-") as td:
        yield Path(td)


def build_scan_env(tempdir: Path) -> dict[str, str]:
    """Build the D-46 env dict on top of the parent ``os.environ``.

    Creates ``tempdir/xdg/`` and ``tempdir/npm/`` so the subprocess
    doesn't have to (some tools refuse to create their cache dir
    themselves). The returned dict is a SHALLOW COPY of ``os.environ``
    with the four keys above overridden; mutating the result does NOT
    affect the parent environment.
    """
    env: dict[str, str] = dict(os.environ)
    xdg_dir = tempdir / "xdg"
    npm_dir = tempdir / "npm"
    xdg_dir.mkdir(parents=True, exist_ok=True)
    npm_dir.mkdir(parents=True, exist_ok=True)
    env["XDG_CACHE_HOME"] = str(xdg_dir)
    env["npm_config_cache"] = str(npm_dir)
    env["NO_COLOR"] = "1"
    env["CI"] = "1"
    return env


@contextmanager
def scan_cache_env(tempdir: Path) -> Iterator[dict[str, str]]:
    """Yield the D-46 env dict scoped to ``tempdir``.

    Convenience wrapper around ``build_scan_env`` that exists because
    the existing Wave 0b test contract (``tests/adapters/test_cache_env.py``)
    consumes it as a context manager. The ``tempdir`` itself is NOT
    deleted here — callers that want auto-cleanup should wrap this in
    a ``scan_tempdir()`` block::

        with scan_tempdir() as td, scan_cache_env(td) as env:
            subprocess.run([...], env=env, ...)

    The env dict yielded here does NOT leak into ``os.environ`` — it
    is a snapshot copy.
    """
    env = build_scan_env(tempdir)
    try:
        yield env
    finally:
        # No-op cleanup; the tempdir lifecycle is owned by the caller
        # (typically ``scan_tempdir()``). We deliberately do NOT touch
        # ``os.environ`` — the parent process's env is never mutated by
        # this helper, so there is nothing to roll back.
        pass
