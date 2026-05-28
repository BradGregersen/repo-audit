"""Post-flight git-status integrity helpers (D-33, Pitfall 9).

snapshot_git_status() runs BEFORE collectors execute; diff_git_status()
compares pre and post sets. Any line in post-pre that isn't under
docs/state-reports/ is an integrity alert (collectors wrote to the
target repo by mistake — bug). Plan 02-06 wires this into cli.scan.

--no-optional-locks (git 2.15+) avoids the index-refresh side-effect
that would otherwise make the snapshot itself the violation (Pitfall 9).
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def snapshot_git_status(repo_path: Path) -> set[str]:
    """Return the set of porcelain-status lines. Empty set on failure (graceful)."""
    try:
        result = subprocess.run(
            [
                "git", "-C", str(repo_path),
                "status", "--porcelain", "-uall", "--no-optional-locks",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {line for line in result.stdout.splitlines() if line}


def diff_git_status(
    pre: set[str],
    post: set[str],
    *,
    allowed_prefix: str = "docs/state-reports/",
) -> list[str]:
    """Return post-only lines whose path is NOT under allowed_prefix.

    Each porcelain line is `XY path` (2-char status + space + path).
    We allow lines whose path starts with allowed_prefix.
    """
    new_lines = post - pre
    offenders: list[str] = []
    for line in new_lines:
        # porcelain format: "XY path" — path starts at column 3
        path = line[3:] if len(line) >= 3 else line
        # Handle rename: "R  old -> new" — only the new path is the "addition"
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if not path.startswith(allowed_prefix):
            offenders.append(line)
    return offenders
