"""D-45 project-local + walk-up + PATH-fallback tool resolution.

The TypeScript adapter (and every future stack adapter that ships
binaries in ``node_modules/.bin`` or equivalent) MUST resolve tool
paths through this helper rather than calling ``shutil.which`` directly.
The walk-up step is the structural mitigation for T-03-03 (PATH-hijack):
a malicious ``tsc`` shim earlier on the user's ``$PATH`` is bypassed
when the target repo ships its own ``node_modules/.bin/tsc``.

Resolution order:

    1. ``<scan_target>/node_modules/.bin/<tool>`` — project-local.
       This is the path the user installed when they ran ``npm install``.
    2. Walk-up: try each ancestor directory's ``node_modules/.bin/<tool>``,
       stopping when an ancestor contains ``.git`` (the conventional
       repo root marker). This handles monorepo workspace layouts where
       ``node_modules`` is hoisted to the repo root rather than
       per-package.
    3. ``shutil.which(<tool>)`` — system PATH fallback. Last resort;
       returns whatever a plain shell would resolve.

Returns ``None`` when none of the three steps succeed. The adapter
maps a ``None`` return to ``AdapterResult(status='unavailable')`` for
that tool — the scan continues with the remaining tools.
"""
from __future__ import annotations

import shutil
from pathlib import Path


def resolve_tool(tool: str, scan_target: Path) -> Path | None:
    """Resolve ``tool`` to an absolute path under ``scan_target`` or ``$PATH``.

    Args:
        tool: bare tool name (``"tsc"``, ``"eslint"``, ``"knip"``).
        scan_target: the directory the adapter is scanning. Project-local
            lookup is rooted here; walk-up climbs from here.

    Returns:
        Absolute ``Path`` to the resolved tool, or ``None`` when the
        tool is not found in project-local, walk-up, or system PATH.
    """
    # 1. Project-local lookup — the highest-priority hit.
    local = scan_target / "node_modules" / ".bin" / tool
    if local.is_file():
        return local

    # 2. Walk-up to the git-root marker.
    current = scan_target
    while True:
        candidate = current / "node_modules" / ".bin" / tool
        if candidate.is_file():
            return candidate
        # Stop at the repo root (``.git/`` present) or the filesystem root.
        if (current / ".git").exists():
            break
        if current.parent == current:
            break
        current = current.parent

    # 3. PATH fallback — last resort.
    which = shutil.which(tool)
    if which:
        return Path(which)
    return None
