"""JS/TS dependency-graph predicate (Phase 14, Plan 02 — ARCH-01).

``has_js_dependency_graph(detection)`` is the read-only, call-time predicate that
gates the WHOLE architecture step (depcruise circular deps + jscpd duplication):
dependency-cruiser and jscpd analyze a JavaScript/TypeScript dependency graph, so
they are only applicable on a JS/TS stack. On every other stack (and a no-stack
repo) the architecture step degrades to a first-class ``not_applicable`` WITHOUT
invoking either tool (RESEARCH Discretion #5 / A3) — the honest cross-stack
not-applicable degrade that mirrors ``adapters/cicd/detect`` and
``adapters/sast/select_packs``.

The three JS-stack literals are the EXACT detector tags emitted by
``detect/rules.py`` (``typescript-node`` / ``expo`` / ``react-native``). A
polyglot repo that includes ANY one of them still has an analyzable JS graph →
``True``. ``supabase`` composes onto an app stack but is NOT itself a JS
dependency-graph stack, so a supabase-ONLY detection is ``False``.

The predicate consumes ``detection.stacks`` (the detector's stack tags), NOT a
filesystem glob — the detector is the single source of truth for "what stacks
this repo has" (RESEARCH Discretion #5). Read-only, no module-load caching.
"""
from __future__ import annotations

from collections.abc import Iterable

# The EXACT JS-stack literals emitted by detect/rules.py MANIFEST_RULES.
# Keep in lockstep with that table — these are the tags, not display names.
_JS_STACKS: frozenset[str] = frozenset({"typescript-node", "expo", "react-native"})


def has_js_dependency_graph(stacks: Iterable[str]) -> bool:
    """Return True iff ``stacks`` includes a JS/TS dependency-graph stack.

    Args:
        stacks: the detector's stack tags for the repo (e.g.
            ``["expo", "kotlin-android"]``). Accepts any iterable of strings —
            typically ``detection.stacks``.

    Returns:
        ``True`` if ANY tag is one of ``typescript-node`` / ``expo`` /
        ``react-native`` (an analyzable JS dependency graph is present);
        ``False`` for every non-JS stack, a supabase-only detection, and an
        empty/no-stack repo (the first-class ``not_applicable`` degrade — the
        architecture tools are NEVER invoked in that case).
    """
    return any(stack in _JS_STACKS for stack in stacks)


__all__ = ["has_js_dependency_graph"]
