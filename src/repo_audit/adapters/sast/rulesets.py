"""SAST ruleset selection — detected stacks → Semgrep registry packs (Plan 10-02).

A small, data-driven map from the detector's stack-name literals (see
``detect/rules.py`` / ``schema/detection.py``) to the Semgrep registry packs that
apply. Two packs are ALWAYS selected (``p/owasp-top-ten`` security baseline +
``p/secrets``); per-stack packs add to those.

Design (10-RESEARCH Architecture Pattern 3): a Python dict, NOT an
``adapter.yaml`` — the table is tiny and adding a new stack→pack mapping in
Phase 11 (``p/python``, ``p/kotlin``) is a ONE-LINE edit here, not a code change.
Selection is deterministic: the always-packs come first, then per-stack packs in
the order the stacks were detected, deduped while preserving first-seen order
(a repo with both ``expo`` + ``typescript-node`` yields each pack once).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_audit.schema.detection import DetectionResult

# Always-on packs: the OWASP Top Ten security baseline + the secrets ruleset.
# These run regardless of the detected stack (every repo gets the security floor).
_ALWAYS: tuple[str, ...] = ("p/owasp-top-ten", "p/secrets")

# Per-stack packs, keyed by the detector's exact stack-name literal
# (detect/rules.py). Phase 11 adds p/python / p/kotlin here as one-line edits.
_STACK_PACKS: dict[str, tuple[str, ...]] = {
    "typescript-node": ("p/typescript",),
    "expo": ("p/react",),
    "react-native": ("p/react",),
}


def select_packs(detection: "DetectionResult") -> list[str]:
    """Select the Semgrep registry packs for a detected repo, deterministically.

    Returns the two always-on packs (``p/owasp-top-ten``, ``p/secrets``) followed
    by every per-detected-stack pack, deduped while preserving first-seen order.
    The result is stable across runs for the same detection (CRIT/reproducibility):
    identical input → identical ordered list.

    Args:
        detection: the stack-detection result; only ``detection.stacks[].stack``
            (the stack-name literal) is consulted.

    Returns:
        An ordered, de-duplicated ``list[str]`` of ``p/...`` pack identifiers.
        A repo with no recognized stack still gets ``["p/owasp-top-ten",
        "p/secrets"]`` (the security floor always applies).
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(pack: str) -> None:
        if pack not in seen:
            seen.add(pack)
            ordered.append(pack)

    for pack in _ALWAYS:
        _add(pack)
    for profile in detection.stacks:
        for pack in _STACK_PACKS.get(profile.stack, ()):
            _add(pack)

    return ordered


__all__ = ["select_packs"]
