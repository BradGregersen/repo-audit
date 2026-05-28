"""Closed-set string types for Finding fields.

Using Literal (not StrEnum) keeps JSON serialization as plain strings
and gives the same validation strictness at construction time.
"""
from typing import Literal

# SCH-02 — the 7-dimension taxonomy from PROJECT.md
Dimension = Literal[
    "security",
    "architecture_rot",
    "test_integrity",
    "correctness",
    "quality",
    "process",
    "observability",
]

# SCH-05 — severity rubric
Severity = Literal["blocker", "critical", "major", "minor", "info"]

# SCH-03 — evidence type vocabulary (SAFE-01 static ≠ runtime)
# Decision C (Plan 03-01a): 5th variant 'failed' added — semantically distinct
# from 'unavailable'. 'unavailable' = tool not present / stale artifact;
# 'failed' = tool ran but produced no usable result (consumed by plan 03-03's
# _refresh_failed_finding helper and plan 03-05's CLI failure-synthesis path).
EvidenceType = Literal[
    "static",
    "runtime",
    "heuristic",
    "unavailable",  # tool not present / stale artifact
    "failed",       # tool ran but produced no usable result
]

# SCH-04 — confidence ladder (rungs that dead-code findings respect)
Confidence = Literal["high", "medium", "candidate", "corroborated", "confirmed"]
