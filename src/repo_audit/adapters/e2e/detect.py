"""E2E harness tri-state detection (E2E-01, Plan 16-02).

READ-ONLY detection of whether the target repo declares a Detox / Maestro /
Playwright end-to-end harness. The lane's defining behavior is a TRI-STATE
(D-16-02): "no E2E configured" (none) vs "harness present but not run"
(present + the run step decides unavailable) vs "ran" (the run step decides
ok/partial). This module owns the *none vs present* distinction only; the
:mod:`repo_audit.adapters.e2e` run step decides the "ran" leg.

The probe mirrors ``test_depth._any_manifest_present`` verbatim in discipline:
existence checks (plus, for Maestro, a bounded CONTENT signal per RESEARCH §A4)
that NEVER raise. Any probe error is treated as "applicable" → returns
``"present"`` (fail-DISCLOSED, never fail-skipped — Pitfall 1: never collapse a
present-but-unrun harness into ``none``).

NO file is ever written; NO spec is ever authored (D-25). This module reads.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

# Playwright config manifests — pure existence is a sufficient signal.
_PLAYWRIGHT_MANIFESTS: tuple[str, ...] = (
    "playwright.config.ts",
    "playwright.config.js",
)
# Detox config manifests — pure existence is a sufficient signal.
_DETOX_MANIFESTS: tuple[str, ...] = (".detoxrc.js", ".detoxrc.json")
# Directories a Maestro flow corpus conventionally lives under.
_MAESTRO_DIRS: tuple[str, ...] = ("maestro", ".maestro")
# RESEARCH §A4 — a Maestro flow YAML is identified by the CONTENT signal, not
# pure existence: a flow declares the app under test (``appId:``) and an action
# to launch it (a ``launchApp`` token). A bare ``*.yaml`` under ``maestro/`` is
# NOT, on its own, a Maestro harness.
_MAESTRO_APPID_TOKEN: str = "appId:"
_MAESTRO_LAUNCH_TOKEN: str = "launchApp"
# Bound the per-file read so a hostile/huge YAML can never exhaust memory.
_MAESTRO_READ_CAP: int = 64 * 1024  # 64 KB is far beyond any real flow file.


def _any_manifest_present(repo_path: Path, names: tuple[str, ...]) -> bool:
    """READ-ONLY: True when any of ``names`` exists directly under ``repo_path``.

    Mirrors ``test_depth._any_manifest_present``: a best-effort existence probe
    that NEVER raises. A probe error is treated as "present" (disclose, don't
    skip) so a harness we could not prove absent is never silently dropped.
    """
    try:
        return any((Path(repo_path) / name).is_file() for name in names)
    except OSError:
        # Could not prove absence → treat as applicable (fail-disclosed).
        return True


def _has_maestro_flow(repo_path: Path) -> bool:
    """READ-ONLY content probe for a Maestro flow corpus (RESEARCH §A4).

    Scans ``maestro/`` / ``.maestro/`` for a ``*.yaml`` / ``*.yml`` whose first
    ``_MAESTRO_READ_CAP`` bytes carry BOTH the ``appId:`` and a ``launchApp``
    token — the content signal that distinguishes a Maestro flow from an
    unrelated YAML. Bounded read, NEVER raises; any error → fail-disclosed True.
    """
    try:
        for dir_name in _MAESTRO_DIRS:
            flows_dir = Path(repo_path) / dir_name
            if not flows_dir.is_dir():
                continue
            for pattern in ("*.yaml", "*.yml"):
                for flow in flows_dir.rglob(pattern):
                    try:
                        text = flow.read_text(encoding="utf-8", errors="ignore")[
                            :_MAESTRO_READ_CAP
                        ]
                    except OSError:
                        # A single unreadable flow file → disclose, don't skip.
                        return True
                    if _MAESTRO_APPID_TOKEN in text and _MAESTRO_LAUNCH_TOKEN in text:
                        return True
        return False
    except OSError:
        # Could not prove absence of a Maestro corpus → fail-disclosed.
        return True


def detected_harnesses(repo_path: Path) -> list[str]:
    """Name which E2E harness(es) the repo declares (for the D-16-02 note text).

    Returns a stable-ordered list drawn from ``{"playwright","detox","maestro"}``;
    an empty list means no harness was detected. READ-ONLY, NEVER raises.
    """
    found: list[str] = []
    if _any_manifest_present(repo_path, _PLAYWRIGHT_MANIFESTS):
        found.append("playwright")
    if _any_manifest_present(repo_path, _DETOX_MANIFESTS):
        found.append("detox")
    if _has_maestro_flow(repo_path):
        found.append("maestro")
    return found


def harness_state(repo_path: Path) -> Literal["none", "present"]:
    """Tri-state precursor: ``"none"`` (no harness) or ``"present"`` (≥1 harness).

    Mirrors ``test_depth._any_manifest_present`` discipline: the run step turns
    ``"present"`` into the "ran" leg; this function NEVER claims "ran". A probe
    that cannot prove absence resolves to ``"present"`` (Pitfall 1 — never
    collapse a configured-but-unrun harness into ``"none"``). NEVER raises.
    """
    return "present" if detected_harnesses(Path(repo_path)) else "none"


__all__ = ["harness_state", "detected_harnesses"]
