"""HEAD commit SHA via pygit2 (D-12).

Phase 1 only reads the SHA. Phase 2's cadence collector will use the same
Repository object for full log walks.
"""
from __future__ import annotations

from pathlib import Path

import pygit2


class NotAGitRepo(Exception):
    """Raised when the target path is not inside a git repository."""


UNCOMMITTED_MARKER = "UNCOMMITTED"  # D-12 + Pitfall 3 fallback


def head_sha(repo_path: Path) -> str:
    """Return the full HEAD commit SHA (40-char hex).

    Edge cases:
    - Path is not a git repo -> raises NotAGitRepo
    - Repo has no commits yet (fresh `git init`) -> returns 'UNCOMMITTED'
    """
    try:
        repo = pygit2.Repository(str(repo_path))
    except pygit2.GitError as e:
        raise NotAGitRepo(f"{repo_path} is not a git repo") from e
    try:
        return str(repo.head.target)
    except (pygit2.GitError, KeyError):
        # Fresh `git init` with no commits -- repo.head raises.
        return UNCOMMITTED_MARKER
