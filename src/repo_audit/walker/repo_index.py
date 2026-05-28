"""RepoIndex walker (D-26..D-29).

Walks a target repo ONCE per scan and produces a metadata-only index that
filename-based collectors (file-size cap, TODO markers, doc presence,
secret detection's working-tree pass) iterate later.

Hard contract (load-bearing):
    * Metadata only -- NO file content reads (D-27, Pitfall 6). Only
      ``os.stat()`` is invoked per file.
    * Symlinks are NOT followed (Pitfall 3). ``os.walk(followlinks=False)``
      plus a per-entry ``is_symlink()`` guard keeps cyclic symlinks from
      causing infinite recursion.
    * Hard cap at ``FILE_CAP = 200_000`` indexed files (D-29). When the cap
      is hit, walker truncates, sets ``status='partial'`` and populates
      ``notes`` describing where the truncation happened.
    * The tool's own output directory (``docs/state-reports/``) is excluded
      at the repo-root level so yesterday's report isn't re-walked
      (Pitfall 7). The skip is tagged with ``SkipReason='build-artifact'``.
    * ``DEFAULT_SKIP_DIRS`` (a ``dict[str, SkipReason]``) maps directory
      names to skip-reason literals; Phase 7 user-config will layer
      per-repo additions on top of this mapping.

Performance: ``os.walk`` is preferred over ``pathlib.Path.rglob`` because
``os.walk`` lets us prune ``dirnames`` in-place mid-iteration (2-3x faster
on large trees per the Phase 2 research notes).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS, SkipReason


# D-29: hard cap; above this the walker truncates and reports status='partial'.
FILE_CAP: int = 200_000


@dataclass(frozen=True)
class FileMeta:
    """Per-D-27: metadata only (path + size_bytes + ext). No content reads."""

    path: Path
    size_bytes: int
    ext: str


@dataclass
class WalkerResult:
    """Output of ``build_repo_index``.

    ``index`` -- the metadata map keyed by ``Path``.
    ``scanned_dirs`` -- top-level dirs the walker entered (for the scope
        ledger's Scanned subsection).
    ``skipped_dirs`` -- ``(dir_path, reason)`` rows auto-logged from
        ``DEFAULT_SKIP_DIRS`` matches and the ``docs/state-reports/``
        self-exclusion.
    ``status`` -- ``'ok'`` when the full tree fit under ``FILE_CAP``;
        ``'partial'`` when the cap was hit and walking was truncated.
    ``notes`` -- human-readable detail (e.g., where the truncation
        happened) populated only when ``status='partial'``.
    """

    index: dict[Path, FileMeta]
    scanned_dirs: list[Path]
    skipped_dirs: list[tuple[Path, SkipReason]]
    status: Literal["ok", "partial"] = "ok"
    notes: str = ""


def build_repo_index(repo_path: Path) -> WalkerResult:
    """Build the RepoIndex for ``repo_path``.

    Contract:
        * Metadata-only walk (no file content reads).
        * Symlinks not followed.
        * ``DEFAULT_SKIP_DIRS`` matches are pruned and auto-logged.
        * ``docs/state-reports/`` at the repo root is pruned with
          ``SkipReason='build-artifact'`` (Pitfall 7).
        * Truncates at ``FILE_CAP`` indexed files (D-29), reporting
          ``status='partial'`` plus a ``notes`` line.

    Args:
        repo_path: Path to the target repo root.

    Returns:
        A ``WalkerResult`` with the index, scanned/skipped dirs, status,
        and notes.
    """
    repo_path = Path(repo_path).resolve()
    index: dict[Path, FileMeta] = {}
    scanned_dirs: list[Path] = []
    skipped_dirs: list[tuple[Path, SkipReason]] = []
    status: Literal["ok", "partial"] = "ok"
    notes = ""

    truncated = False
    for dirpath, dirnames, filenames in os.walk(repo_path, followlinks=False):
        current = Path(dirpath)
        keep: list[str] = []
        for d in dirnames:
            # 1) DEFAULT_SKIP_DIRS table.
            reason = DEFAULT_SKIP_DIRS.get(d)
            if reason is not None:
                skipped_dirs.append((current / d, reason))
                continue
            # 2) Pitfall 7 -- docs/state-reports/ at the repo root.
            #    Only prune when the parent IS the repo root (we don't want to
            #    silently skip a vendored sub-project's docs/state-reports/).
            if current == repo_path and d == "docs":
                # Check whether the docs/ contains a state-reports/ child;
                # if so, do NOT prune all of docs/ -- only the state-reports/
                # sub-dir is the tool's output. We keep walking into docs/
                # and the special-case prune happens one level deeper below.
                keep.append(d)
                continue
            if (
                current.parent == repo_path
                and current.name == "docs"
                and d == "state-reports"
            ):
                skipped_dirs.append((current / d, "build-artifact"))
                continue
            keep.append(d)
        # In-place prune so os.walk doesn't descend into skipped dirs.
        dirnames[:] = keep
        # Record scanned subdirs only at the repo-root iteration so we don't
        # blow up the ledger with every nested directory.
        if current == repo_path:
            scanned_dirs = [current / d for d in keep]

        for fname in filenames:
            full = current / fname
            # Pitfall 3 -- skip symlinks (broken or cyclic).
            try:
                if full.is_symlink():
                    continue
            except OSError:
                continue
            try:
                stat = full.stat()
            except OSError:
                # Broken symlink, permission denied, or vanished mid-walk.
                continue
            index[full] = FileMeta(
                path=full,
                size_bytes=stat.st_size,
                ext=full.suffix.lower(),
            )
            if len(index) >= FILE_CAP:
                truncated = True
                notes = (
                    f"Walker hit {FILE_CAP}-file cap at {current}; "
                    f"remaining files unindexed."
                )
                break
        if truncated:
            break

    if truncated:
        status = "partial"

    return WalkerResult(
        index=index,
        scanned_dirs=scanned_dirs,
        skipped_dirs=skipped_dirs,
        status=status,
        notes=notes,
    )
