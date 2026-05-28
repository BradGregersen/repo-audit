"""Repo-slug derivation (D-16).

basename.lower() -> non-alphanumeric collapsed to '-' -> strip leading/trailing '-'.
"""
from __future__ import annotations

import re
from pathlib import Path

_SLUG_RX = re.compile(r"[^a-z0-9]+")


def repo_slug(repo_path: Path) -> str:
    """D-16: basename, lowercased, non-alphanumeric collapsed to '-'.

    Examples:
        ~/Code/adapt -> 'adapt'
        ~/Code/Repo Command center -> 'repo-command-center'
        ~/Code/repo-asg-client-fork -> 'repo-asg-client-fork'
    """
    name = Path(repo_path).resolve().name.lower()
    slug = _SLUG_RX.sub("-", name).strip("-")
    if not slug:
        raise ValueError(f"cannot derive repo slug from {repo_path!r}")
    return slug
