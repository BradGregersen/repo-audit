"""Walk a repo, match manifest patterns, resolve overrides, return DetectionResult.

Algorithm:
    1. walk_for_manifests(repo) → {directory_path: {filenames}}
    2. For each directory, try every StackRule. A rule matches when:
       - all of `requires_all` are present (after glob expansion), AND
       - if requires_any is non-empty, at least one of those is present
    3. When a rule matches, build a StackProfile with confidence
       = base_confidence + 0.05 * |boosts_if_any matches|, capped at 1.0
    4. Resolve overrides: for each directory, if rule X matched and any
       matched rule Y has `X.name in Y.overrides`, drop X for that directory
    5. Return DetectionResult(stacks=[...])
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

from repo_audit.detect.rules import MANIFEST_RULES, StackRule
from repo_audit.detect.walker import walk_for_manifests
from repo_audit.schema.detection import DetectionResult, StackProfile


def _is_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


def _files_matching(pattern: str, files: set[str]) -> list[str]:
    """Return all filenames matching pattern (exact or fnmatch glob)."""
    if _is_glob(pattern):
        return [f for f in files if fnmatch.fnmatch(f, pattern)]
    if pattern in files:
        return [pattern]
    return []


def _rule_matches(rule: StackRule, files: set[str]) -> tuple[bool, list[str]]:
    """Return (matched, list_of_matching_filenames)."""
    matches: list[str] = []
    # requires_all: every pattern must produce ≥1 match
    for pat in rule.requires_all:
        ms = _files_matching(pat, files)
        if not ms:
            return False, []
        matches.extend(ms)
    # requires_any: at least one pattern must produce ≥1 match (if non-empty)
    if rule.requires_any:
        any_hit = False
        for pat in rule.requires_any:
            ms = _files_matching(pat, files)
            if ms:
                matches.extend(ms)
                any_hit = True
        if not any_hit:
            return False, []
    return True, matches


def _rule_confidence(rule: StackRule, files: set[str]) -> float:
    c = rule.base_confidence
    for pat in rule.boosts_if_any:
        if _files_matching(pat, files):
            c = min(1.0, c + 0.05)
    return c


def detect_stacks(repo_path: Path) -> DetectionResult:
    """Walk the repo, match rules per directory, resolve overrides.

    DETECT-03: returns DetectionResult(stacks=[]) on a repo with no
    recognized manifests — caller should NOT treat this as an error.
    DETECT-02: per-directory matches produce distinct StackProfile records
    with their own root_dir.
    """
    repo_path = Path(repo_path).resolve()
    manifests_by_dir = walk_for_manifests(repo_path)

    per_dir_profiles: list[tuple[Path, StackRule, list[str]]] = []

    for dir_path, files in manifests_by_dir.items():
        # Find all matching rules in this directory
        matched_here: list[tuple[StackRule, list[str]]] = []
        for rule in MANIFEST_RULES:
            ok, matches = _rule_matches(rule, files)
            if ok:
                matched_here.append((rule, matches))
        if not matched_here:
            continue
        # Resolve overrides: drop any rule X where some matched Y has X.name in Y.overrides
        override_targets: set[str] = set()
        for rule, _ in matched_here:
            override_targets.update(rule.overrides)
        for rule, matches in matched_here:
            if rule.name in override_targets:
                continue
            per_dir_profiles.append((dir_path, rule, matches))

    stacks: list[StackProfile] = []
    for dir_path, rule, matches in per_dir_profiles:
        # Use walker-known files for confidence calc (same set used to match)
        files = manifests_by_dir.get(dir_path, set())
        stacks.append(
            StackProfile(
                stack=rule.name,
                root_dir=dir_path,
                manifests=[Path(m) for m in sorted(set(matches))],
                confidence=_rule_confidence(rule, files),
            )
        )

    return DetectionResult(stacks=stacks)
