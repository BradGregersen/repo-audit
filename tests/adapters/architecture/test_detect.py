"""ARCH detect-and-degrade contract (Plan 14-02/03, Wave-1/2).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the
implementation ``repo_audit.adapters.architecture.detect`` lands (the
03-01b SKIPPED→ACTIVE-on-landing discipline), at which point these contract
assertions activate automatically.

``has_js_dependency_graph(detection)`` is the predicate that gates the whole
architecture step: the three JS-stack literals (``typescript-node``, ``expo``,
``react-native``) have an analyzable JS dependency graph; every other stack
(and a no-stack repo) does NOT → ``run_architecture`` degrades to
``not_applicable`` WITHOUT invoking depcruise/jscpd (the first-class degrade,
RESEARCH Discretion #5 / A3). ``supabase`` composes onto an app stack but is not
itself a JS dependency-graph stack.
"""
from __future__ import annotations

import pytest

detect = pytest.importorskip(
    "repo_audit.adapters.architecture.detect",
    reason="optional module repo_audit.adapters.architecture.detect not importable — feature not present in this build, or the install is incomplete",
)


@pytest.mark.parametrize("stack", ["typescript-node", "expo", "react-native"])
def test_js_stacks_have_dependency_graph(stack: str) -> None:
    """The three JS stacks expose an analyzable dependency graph → True."""
    assert detect.has_js_dependency_graph([stack]) is True


@pytest.mark.parametrize(
    "stack",
    ["kotlin-android", "python", "rust", "go", "cpp", "csharp", "supabase"],
)
def test_non_js_stacks_have_no_dependency_graph(stack: str) -> None:
    """Non-JS stacks (incl. supabase-only) → False (not_applicable degrade)."""
    assert detect.has_js_dependency_graph([stack]) is False


def test_empty_detection_is_false() -> None:
    """A repo with no detected stack has no JS dependency graph."""
    assert detect.has_js_dependency_graph([]) is False


def test_mixed_stack_with_one_js_is_true() -> None:
    """A polyglot repo that includes ONE JS stack still has a graph → True."""
    assert detect.has_js_dependency_graph(["kotlin-android", "expo"]) is True
