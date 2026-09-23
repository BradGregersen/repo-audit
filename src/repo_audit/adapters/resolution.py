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

``trusted_only`` contract (CR-01)
---------------------------------
Steps 1-2 resolve a binary out of the **untrusted scanned repo** (the target's
own ``node_modules/.bin``). For npm PROJECT tools (tsc/eslint/knip/expo/
stryker/type-coverage) that is the *intended* T-03-03 PATH-hijack mitigation:
we deliberately prefer the binary the user installed in their repo over a
PATH shim. But for VENDORED / SYSTEM SECURITY scanners (syft, osv-scanner,
grype, semgrep, detekt, java, node, squawk, pgrls, …) it is a vulnerability:
when our vendored binary is ABSENT (any non-``linux_amd64`` platform — only
that arch is vendored — or a removed/corrupt binary), resolution falls through
to steps 1-2 and EXECUTES a binary a hostile target repo planted, with
``cwd=scan_target`` → arbitrary code execution.

Pass ``trusted_only=True`` for every security-scanner call site. In that mode
resolution is restricted to step 0 (our vendored binary) and step 3 (system
``$PATH``) — the untrusted target-repo node_modules steps (1-2) are SKIPPED
entirely, so a planted ``node_modules/.bin/<tool>`` can never be selected.
The default ``trusted_only=False`` preserves the project-tool behavior.
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


def resolve_tool(
    tool: str, scan_target: Path, *, trusted_only: bool = False
) -> Path | None:
    """Resolve ``tool`` to an absolute path under ``scan_target`` or ``$PATH``.

    Args:
        tool: bare tool name (``"tsc"``, ``"eslint"``, ``"knip"``).
        scan_target: the directory the adapter is scanning. Project-local
            lookup is rooted here; walk-up climbs from here.
        trusted_only: when ``True`` (CR-01), resolve ONLY the vendored binary
            (step 0) or a system ``$PATH`` entry (step 3); the untrusted
            target-repo ``node_modules`` steps (1-2) are SKIPPED. Use for
            vendored/system SECURITY scanners so a binary a hostile target repo
            planted can never be executed. Default ``False`` keeps the full
            ladder (the intended T-03-03 mitigation for npm PROJECT tools).

    Returns:
        Absolute ``Path`` to the resolved tool, or ``None`` when the
        tool is not found in project-local, walk-up, or system PATH.
    """
    # 0. Vendored static binary — the highest-priority hit (D-06-10).
    vendored = _vendor_binary(tool)
    if vendored is not None:
        return vendored

    # Steps 1-2 resolve out of the UNTRUSTED target repo. For security scanners
    # (trusted_only=True) we skip them to close CR-01 and go straight to PATH.
    if not trusted_only:
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
