"""SAST-02 / CRIT-2 — deterministic noise floor (path-exclude + severity floor).

Semgrep over a real repo produces findings in test fixtures, mocks, generated
code and vendored dependencies that are NOT actionable signal — they are noise.
:func:`apply_noise_floor` drops them BEFORE any finding reaches the report
(CRIT-2: "before any finding reaches the report"), along with findings strictly
below a severity floor (default: ``info`` is dropped, ``minor`` and up kept).

Both halves are deterministic and OVERRIDABLE: an ``.repo-audit.yaml``
``sast`` block (passed as the ``override`` dict) can replace the default exclude
list and/or the severity floor. Following the existing scoped-config posture
(``collectors/file_size_cap``, ``collectors/secret_detection``) there is NO
central config loader — the caller (Plan 10-03) reads the repo's ``sast`` block
under ruamel ``YAML(typ="safe")`` and hands the resolved dict in here. The
override only supplies scalars (a string floor + a list of path substrings); it
never executes code (threat T-10-02-03 mitigation).

Match semantics: an exclude entry drops a finding when it appears as a
``/``-delimited PATH SEGMENT of ``finding.file`` OR (for dotted markers like
``.generated.``) as a substring of any segment. This is gitignore-flavoured
enough for the default set without pulling in a glob/regex engine — an override
list only ever widens the set of plain substring matches (threat T-10-02-04
accepted: no user regex, so no ReDoS surface).
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Finding

# Default path excludes. Each entry matches a path SEGMENT of finding.file
# (e.g. "node_modules" matches "node_modules/lib/index.js"); the dotted markers
# (".generated.") match as a substring of any segment (e.g. "api.generated.ts"
# and the "generated" directory both drop).
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "node_modules",
    "build",
    ".expo",
    "dist",
    "vendor",
    "__tests__",
    "__mocks__",
    "__fixtures__",
    "generated",
    ".generated.",
)

# Default severity floor: drop findings STRICTLY below this rung. "minor" means
# 'info' is dropped, 'minor' and above are kept.
DEFAULT_SEVERITY_FLOOR: str = "minor"

# Severity rungs low -> high (schema/enums.Severity). Used for the floor compare.
_RANK: dict[str, int] = {
    "info": 0,
    "minor": 1,
    "major": 2,
    "critical": 3,
    "blocker": 4,
}


def _path_excluded(file: str | None, excludes: tuple[str, ...]) -> bool:
    """True when ``file`` matches any exclude as a path segment / segment-substring.

    A finding with no file (``file is None``) is never path-excluded (it cannot
    live in a test/vendor dir we can name). For each exclude entry we check
    every ``/``-delimited segment of the path: an exact-segment match drops it,
    and a dotted marker (``.generated.``) drops on a substring match within a
    segment so both ``src/generated/api.ts`` and ``src/api.generated.ts`` are
    covered.
    """
    if not file:
        return False
    segments = file.replace("\\", "/").split("/")
    for entry in excludes:
        for seg in segments:
            if seg == entry:
                return True
            if entry.startswith(".") and entry in seg:
                return True
    return False


def apply_noise_floor(
    findings: list[Finding],
    *,
    override: dict[str, Any] | None = None,
) -> list[Finding]:
    """Drop test/mock/generated/vendored-path AND sub-floor-severity findings.

    Deterministic and order-preserving (CRIT-2): identical input yields an
    identical kept subset, in input order. Resolves the exclude list + severity
    floor from ``override`` at CALL time (the scoped ``.repo-audit.yaml``
    ``sast`` block dict), defaulting to :data:`DEFAULT_EXCLUDES` /
    :data:`DEFAULT_SEVERITY_FLOOR` when absent — so the floor is overridable
    without a central config system.

    Args:
        findings: the candidate findings (e.g. from :func:`sarif_to_findings`).
        override: an optional ``sast``-block dict. Recognized keys:
            ``"exclude_paths"`` (``list[str]`` of path substrings/segments that
            REPLACES the defaults) and ``"severity_floor"`` (a Severity string
            that REPLACES the default floor). Unknown keys are ignored.

    Returns:
        The kept findings, in input order. A finding is dropped when its file
        matches an exclude OR its severity ranks strictly below the floor.
    """
    override = override or {}
    excludes_raw = override.get("exclude_paths")
    excludes: tuple[str, ...] = (
        tuple(excludes_raw) if excludes_raw is not None else DEFAULT_EXCLUDES
    )
    floor = override.get("severity_floor") or DEFAULT_SEVERITY_FLOOR
    floor_rank = _RANK.get(floor, _RANK[DEFAULT_SEVERITY_FLOOR])

    kept: list[Finding] = []
    for finding in findings:
        if _path_excluded(finding.file, excludes):
            continue
        if _RANK.get(finding.severity, 0) < floor_rank:
            continue
        kept.append(finding)
    return kept


__all__ = ["apply_noise_floor", "DEFAULT_EXCLUDES", "DEFAULT_SEVERITY_FLOOR"]
