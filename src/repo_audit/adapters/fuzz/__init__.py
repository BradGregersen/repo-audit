"""Fuzz lane (FUZZ-01) — detection re-exports (Task 1; Task 2 adds run_fuzz).

This module is the package surface for the fuzz lane. Task 1 lands the READ-ONLY
detection + config; Task 2 layers the ``run_fuzz`` envelope (split trigger:
fast-check detect-only / native opt-in + budgeted) on top.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from repo_audit.adapters.fuzz.config import FuzzConfig, read_fuzz_config
from repo_audit.adapters.fuzz.detect import (
    FuzzEngine,
    FuzzTarget,
    candidate_surfaces,
    fastcheck_present,
    native_targets,
)
from repo_audit.schema.finding import Finding


@dataclass
class FuzzDetectResult:
    """READ-ONLY detection summary (the ``detect`` entry the lane exposes).

    Carries the fast-check presence signal, the detected native targets, and the
    candidate-surface signals — all gathered without running anything. ``status``
    is ``not_applicable`` when nothing fuzz-related is present, else ``ok``.
    """

    __test__ = False

    fastcheck: bool = False
    targets: list[FuzzTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "not_applicable"


def detect(repo_path: Path) -> FuzzDetectResult:
    """READ-ONLY fuzz detection (Pitfall 4 — never invokes fast-check).

    Gathers the fast-check presence signal, native targets, and candidate-surface
    signals. ``status='ok'`` when any fuzz-related signal is present, else
    ``not_applicable``. Never runs a tool, never writes — pure detection.
    """
    repo = Path(repo_path)
    fc = fastcheck_present(repo)
    targets = native_targets(repo)
    fuzzed = {t.path for t in targets}
    cand = candidate_surfaces(repo, fuzzed)
    has_signal = fc or bool(targets) or bool(cand)
    return FuzzDetectResult(
        fastcheck=fc,
        targets=targets,
        findings=cand,
        status="ok" if has_signal else "not_applicable",
    )


# Naming variant the Wave-0 candidate test tolerates.
candidates = candidate_surfaces

__all__ = [
    "FuzzConfig",
    "read_fuzz_config",
    "FuzzEngine",
    "FuzzTarget",
    "FuzzDetectResult",
    "fastcheck_present",
    "native_targets",
    "candidate_surfaces",
    "detect",
    "candidates",
]
