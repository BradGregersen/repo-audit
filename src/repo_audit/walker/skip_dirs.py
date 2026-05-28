"""Per-D-28: SkipReason taxonomy + DEFAULT_SKIP_DIRS mapping.

Phase 7 user-config will layer per-repo additions on top of this dict.
Phase 1's frozenset[str] in detect/walker.py is kept (it serves manifest
detection, which is separate from Phase 2's RepoIndex walk).
"""
from typing import Literal

SkipReason = Literal[
    "vcs", "dependencies", "build-artifact", "cache", "editor", "test-output",
]

DEFAULT_SKIP_DIRS: dict[str, SkipReason] = {
    ".git": "vcs",
    "node_modules": "dependencies",
    ".venv": "dependencies",
    "venv": "dependencies",
    "vendor": "dependencies",
    "dist": "build-artifact",
    "build": "build-artifact",
    "target": "build-artifact",
    ".next": "build-artifact",
    "__pycache__": "cache",
    ".pytest_cache": "cache",
    ".ruff_cache": "cache",
    ".mypy_cache": "cache",
    ".tox": "cache",
    ".gradle": "cache",
    "coverage": "test-output",
    ".idea": "editor",
    ".vscode": "editor",
}
