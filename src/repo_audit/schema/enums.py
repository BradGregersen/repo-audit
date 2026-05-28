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
EvidenceType = Literal["static", "runtime", "heuristic", "unavailable"]

# SCH-04 — confidence ladder (rungs that dead-code findings respect)
Confidence = Literal["high", "medium", "candidate", "corroborated", "confirmed"]
