"""RN-surface predicate (Phase 15, Plan 03 — PERF-01 RN bundle gate).

``has_rn_surface(stacks)`` is the read-only, call-time predicate that gates the
``react-native bundle`` size sub-step: the Metro bundle build only applies to a
React Native / Expo app. On every other stack (and a no-stack repo) the RN sub-
step is skipped — and if there is ALSO no configured ``live_url`` (the web gate),
``run_quality_depth`` degrades to a first-class ``not_applicable`` WITHOUT
invoking any tool (RESEARCH §Live-URL Config / SAFE-08). This mirrors
``adapters/architecture/detect.has_js_dependency_graph``.

Critically, there is NO ``has_web_surface`` stack predicate here: the WEB
applicability of axe/Lighthouse is gated by the presence of ``live_url`` in
config (providing the URL IS the opt-in — D-15-03), NOT by a detected stack. The
only stack-driven gate in this adapter is the RN-bundle one below.

The two RN-stack literals are the EXACT detector tags emitted by
``detect/rules.py`` (``react-native`` / ``expo``). A polyglot repo that includes
ANY one of them still has an analyzable RN bundle surface → ``True``. Read-only,
no module-load caching.
"""
from __future__ import annotations

from collections.abc import Iterable

# The EXACT RN-stack literals emitted by detect/rules.py MANIFEST_RULES.
# Keep in lockstep with that table — these are the tags, not display names.
_RN_STACKS: frozenset[str] = frozenset({"react-native", "expo"})


def has_rn_surface(stacks: Iterable[str]) -> bool:
    """Return True iff ``stacks`` includes a React Native / Expo surface.

    Args:
        stacks: the detector's stack tags for the repo (e.g.
            ``["expo", "kotlin-android"]``). Accepts any iterable of strings —
            typically ``detection.stacks``.

    Returns:
        ``True`` if ANY tag is ``react-native`` or ``expo`` (a Metro JS bundle
        surface is present, so the ``react-native bundle`` size sub-step
        applies); ``False`` for every non-RN stack and an empty/no-stack repo
        (the RN sub-step is NEVER invoked in that case).
    """
    return any(stack in _RN_STACKS for stack in stacks)


__all__ = ["has_rn_surface"]
