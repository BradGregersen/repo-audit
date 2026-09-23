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
# This COUNT-based cap is the SOLE global hard-stop and the real index-memory
# ceiling: the index is metadata-only (~200 bytes/FileMeta), so 200_000 entries
# is ≈ 40 MB worst case regardless of the target's on-disk size.
FILE_CAP: int = 200_000

# SCAN-BOUND-01 (D-051-06) / SCAN-COVER-01 — defence-in-depth walker bounds.
# The walker is NOT the measured bottleneck (about a second on a very large monorepo); the
# load-bearing fix is the per-file byte ceiling in collectors/file_size_cap.py.
# These caps are insurance so the index can never carry a pathological payload
# regardless of the target's directory layout. The bounds are now a hybrid that
# is ORDER-INDEPENDENT and prunes-and-continues (never a global byte halt):
#   * FILE_CAP (count, above)   -> the sole GLOBAL hard-stop on index size.
#   * MAX_FILE_INDEX_BYTES      -> a single oversized file is SKIPPED (not
#                                  indexed, not counted) so one giant binary
#                                  can't starve a subtree's budget.
#   * SUBTREE_BYTE_CAP          -> per top-level subtree; overflow prunes ONLY
#                                  that subtree (budget-truncated) and the walk
#                                  CONTINUES with sibling top-level dirs. Keyed
#                                  on the first path component so the kept/pruned
#                                  decision does not depend on os.walk order.
#   * MAX_DEPTH = 25            -> real monorepos measured well under this; 25 is generous insurance.
# AGGREGATE on-disk bytes are INTENTIONALLY UNBOUNDED (W1): N subtrees each just
# under SUBTREE_BYTE_CAP can sum large, but that does NOT determine index memory
# — index memory is bounded by FILE_CAP (count), not by bytes. The earlier
# global aggregate-byte cap was removed because it broke coverage: it halted the
# WHOLE walk the moment a big build-artifact subtree tripped it, silently
# dropping every top-level dir that sorted after it (SCAN-COVER-01 bug).
# When any cap trips, the truncated tree/file is recorded as a
# ('budget-truncated') skipped_dirs row so the scope ledger discloses the bound
# (D-051-07 / SAFE-08) — no ledger code change needed.
# Pitfall-4 tradeoff (W3): the per-subtree byte cap is the real order-independent
# fix; the builds/releases name-based skips in DEFAULT_SKIP_DIRS are a
# belt-and-suspenders optimization, disclosed as build-artifact skipped_dirs
# rows so the user SEES them, and accepted because in practice they are
# gitignored build output.
SUBTREE_BYTE_CAP: int = 524_288_000   # 500 MB per top-level subtree
MAX_FILE_INDEX_BYTES: int = 52_428_800  # 50 MB per file
MAX_DEPTH: int = 25


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
    stop_walk = False  # set ONLY by FILE_CAP — the sole global hard-stop
    # Per top-level subtree byte accounting (order-independent). Keyed on the
    # first path component below repo_path; root-level files use the "<root>"
    # sentinel. Overflow prunes only that subtree and the walk continues.
    subtree_bytes: dict[str, int] = {}
    pruned_keys: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(repo_path, followlinks=False):
        current = Path(dirpath)

        # SCAN-BOUND-01 (D-051-06) depth cap. Depth is the number of path
        # components below repo_path; when it exceeds MAX_DEPTH we prune this
        # subtree (clear dirnames in place so os.walk doesn't descend) and
        # record it as budget-truncated. We still index this dir's own files
        # (it is AT the boundary, not beyond it) but go no deeper.
        try:
            depth = len(current.relative_to(repo_path).parts)
        except ValueError:
            depth = 0
        if depth > MAX_DEPTH:
            dirnames[:] = []
            skipped_dirs.append((current, "budget-truncated"))
            truncated = True
            if not notes:
                notes = (
                    f"Walker hit {MAX_DEPTH}-level depth cap at {current}; "
                    f"deeper subtree unindexed."
                )
            continue

        # SCAN-COVER-01 (B2): per-subtree key — the first path component below
        # repo_path, or the "<root>" sentinel for files living directly in
        # repo_path (empty rel.parts). Order-independent: the byte budget is
        # tracked per this key, not per os.walk visitation order.
        rel = current.relative_to(repo_path)
        subtree_key = rel.parts[0] if rel.parts else "<root>"
        # If this subtree already blew its byte budget, prune any deeper dirs
        # and skip — its budget-truncated row was already logged when it tripped.
        if subtree_key in pruned_keys:
            dirnames[:] = []
            continue

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
            # SCAN-COVER-01 (T-0511-02): skip a single oversized file BEFORE
            # indexing. It is not indexed and never counts toward subtree bytes,
            # so one giant binary can't knock out its siblings/subtree. The walk
            # continues; the skip is disclosed as a budget-truncated row.
            if stat.st_size > MAX_FILE_INDEX_BYTES:
                skipped_dirs.append((full, "budget-truncated"))
                truncated = True
                if not notes:
                    notes = (
                        f"Walker skipped oversized file {full} "
                        f"(> {MAX_FILE_INDEX_BYTES} bytes)."
                    )
                continue
            index[full] = FileMeta(
                path=full,
                size_bytes=stat.st_size,
                ext=full.suffix.lower(),
            )
            if len(index) >= FILE_CAP:
                truncated = True
                stop_walk = True
                skipped_dirs.append((current, "budget-truncated"))
                notes = (
                    f"Walker hit {FILE_CAP}-file cap at {current}; "
                    f"remaining files unindexed."
                )
                break
            # SCAN-COVER-01 (T-0511-03): per-subtree byte cap. When a top-level
            # subtree's accumulated indexed bytes exceed SUBTREE_BYTE_CAP, prune
            # ONLY that subtree (clear dirnames so os.walk doesn't descend) and
            # record it as budget-truncated. The `break` exits the FILENAME loop
            # only — os.walk CONTINUES into sibling top-level dirs (the fix).
            subtree_bytes[subtree_key] = (
                subtree_bytes.get(subtree_key, 0) + stat.st_size
            )
            if (
                subtree_bytes[subtree_key] > SUBTREE_BYTE_CAP
                and subtree_key not in pruned_keys
            ):
                pruned_keys.add(subtree_key)
                dirnames[:] = []
                skipped_dirs.append((current, "budget-truncated"))
                truncated = True
                if not notes:
                    notes = (
                        f"Walker hit {SUBTREE_BYTE_CAP}-byte per-subtree cap on "
                        f"'{subtree_key}' at {current}; remaining files in that "
                        f"subtree unindexed."
                    )
                break  # exit the FILENAME loop only; os.walk continues
        if stop_walk:
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
