"""Fleet discovery: immediate ``.git`` children under a sweep root (FLEET-01).

Discovery rules (locked, RESEARCH Pitfall 6):

- IMMEDIATE children only — ``for child in root.iterdir(): (child / ".git").exists()``.
  We test ``.exists()`` (NOT ``.is_dir()``) because ``.git`` is a FILE for git
  worktrees and submodules — a ``.git`` file is a real repo and must be
  discovered. We do NOT recurse: nested repos (a repo inside a repo) are
  ambiguous and out of scope for v1, and recursion is the path to symlink
  loops and runaway sweeps.

- Symlinked children are SKIPPED and recorded (``skipped_symlinks``). This is
  the escape/loop guard (T-05-06): a symlink could point outside the sweep root
  or into a cycle. v1 refuses to follow them; Plan 05-05 surfaces the recorded
  list so the sweep can note "N symlinked dirs skipped".

- Non-repo directories (no ``.git``) and non-directory entries are skipped
  silently.

- Results are returned in a deterministic order (sorted by name) so a fleet
  sweep is reproducible run-to-run (FLEET-01 "sequential").

- A ``PermissionError`` reading the root surfaces as a clean error rather than
  a partial/confusing result. A per-child ``OSError`` (e.g. an unreadable
  child while stat-ing ``.git``) is treated as "not a usable repo" and skipped
  (T-05-07: one bad child must not abort the whole sweep).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DiscoveryResult:
    """Outcome of a discovery pass over a sweep root.

    repos
        Discovered repo directories (each contains a ``.git`` file or dir), in
        deterministic name order.
    skipped_symlinks
        Symlinked children that were refused (escape/loop guard). Recorded so
        Plan 05-05 can note them in the sweep output.
    """

    repos: list[Path] = field(default_factory=list)
    skipped_symlinks: list[Path] = field(default_factory=list)


def discover_repos(root: Path) -> DiscoveryResult:
    """Discover immediate ``.git`` children under ``root``.

    Args:
        root: The sweep root directory (the ``repo-audit fleet <dir>`` argument).

    Returns:
        A :class:`DiscoveryResult` with the discovered repos (deterministic
        order) and any skipped symlinked children.

    Raises:
        NotADirectoryError: if ``root`` is not a directory.
        PermissionError: if ``root`` itself cannot be listed (surfaces cleanly
            rather than returning a misleading empty/partial result).
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"sweep root is not a directory: {root}")

    # PermissionError on the root propagates intentionally (T-05-07: an
    # unreadable ROOT is a real, surfaceable failure — unlike an unreadable
    # single child, which we skip below).
    children = list(root.iterdir())

    repos: list[Path] = []
    skipped_symlinks: list[Path] = []

    for child in children:
        # Escape/loop guard FIRST (T-05-06): never even stat through a symlink.
        if child.is_symlink():
            skipped_symlinks.append(child)
            continue
        try:
            if not child.is_dir():
                continue
            # .exists() (not .is_dir()) — `.git` is a FILE for worktrees/submodules.
            if (child / ".git").exists():
                repos.append(child)
        except OSError:
            # Unreadable child (permissions, vanished mid-walk): skip, don't
            # abort the sweep (T-05-07).
            continue

    repos.sort(key=lambda p: p.name)
    skipped_symlinks.sort(key=lambda p: p.name)
    return DiscoveryResult(repos=repos, skipped_symlinks=skipped_symlinks)
