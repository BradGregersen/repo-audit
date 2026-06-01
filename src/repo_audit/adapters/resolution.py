"""D-45 project-local + walk-up + PATH-fallback tool resolution.

The TypeScript adapter (and every future stack adapter that ships
binaries in ``node_modules/.bin`` or equivalent) MUST resolve tool
paths through this helper rather than calling ``shutil.which`` directly.
The walk-up step is the structural mitigation for T-03-03 (PATH-hijack):
a malicious ``tsc`` shim earlier on the user's ``$PATH`` is bypassed
when the target repo ships its own ``node_modules/.bin/tsc``.

Resolution order:

    0. (D-06-10) ``vendor/<tool>/<tool>`` under the in-package
       ``src/repo_audit/vendor/`` dir — a vendored static binary we
       ship and control. This is the HIGHEST-priority hit: we trust our own
       bundled binary ahead of a project-local shim or a PATH entry
       (T-06-03). The ``vendor/`` dir does not exist yet — the first real
       vendored binary arrives with osv-scanner in Phase 7 — so today this
       step simply misses and falls through, which the resolution tests pin.
    1. ``<scan_target>/node_modules/.bin/<tool>`` — project-local.
       This is the path the user installed when they ran ``npm install``.
    2. Walk-up: try each ancestor directory's ``node_modules/.bin/<tool>``,
       stopping when an ancestor contains ``.git`` (the conventional
       repo root marker). This handles monorepo workspace layouts where
       ``node_modules`` is hoisted to the repo root rather than
       per-package.
    3. ``shutil.which(<tool>)`` — system PATH fallback. Last resort;
       returns whatever a plain shell would resolve.

Returns ``None`` when none of the steps succeed. The adapter
maps a ``None`` return to ``AdapterResult(status='unavailable')`` for
that tool — the scan continues with the remaining tools.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import repo_audit

# In-package vendor root — same location CLAUDE.md uses for vendored ``scc``
# (``src/repo_audit/vendor/scc/``). Module-level so it is greppable and
# monkeypatchable in tests; resolved once at import time.
_VENDOR_ROOT: Path = Path(repo_audit.__file__).parent / "vendor"


def _vendor_binary(tool: str) -> Path | None:
    """Return the vendored ``<tool>/<tool>`` binary path, or ``None`` (D-06-10).

    The lookup is ``_VENDOR_ROOT / tool / tool``. Returns the path only when it
    exists AND is a regular file (a directory at that path is NOT a hit). A
    small dedicated helper keeps the vendor seam greppable and unit-testable
    independent of the full resolution ladder.
    """
    candidate = _VENDOR_ROOT / tool / tool
    if candidate.is_file():
        return candidate
    return None


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
    # 0. Vendored static binary — the highest-priority hit (D-06-10).
    vendored = _vendor_binary(tool)
    if vendored is not None:
        return vendored

    # 1. Project-local lookup.
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
