"""COLL-06: per-ext line-count cap (D-36).

Threshold lookup routes through ``get_threshold(ext)`` so Phase 7's
``.repo-audit.yaml`` overlay swaps just this one function::

    def get_threshold(ext: str) -> int:
        return user_caps.get(
            ext, DEFAULT_SIZE_CAPS.get(ext, DEFAULT_SIZE_CAPS['default']),
        )

Performance (Pattern 6 from 02-RESEARCH.md): coarse byte pre-filter
skips files where ``size_bytes < threshold * BYTES_PER_LINE_FLOOR``
(~40 bytes/line conservative average). On a 50k-file repo this skips
~99% of files before any content read.

Emission rule: one Finding per over-cap file, dimension='quality',
severity='minor', evidence_type='static', confidence='high',
source_tool='in-process', source_collector='file_size_cap'. The
``parsed_value`` block carries the relative path, observed line_count,
applied threshold, overage (line_count - threshold), and the ext that
selected the threshold -- enough for Phase 5 trend deltas and Phase 4
narrative without re-reading the file.
"""
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.finding import Evidence, Finding


DEFAULT_SIZE_CAPS: dict[str, int] = {
    ".tsx": 200,
    ".ts": 300,
    ".js": 300,
    ".py": 300,
    ".kt": 300,
    "default": 300,
}

BYTES_PER_LINE_FLOOR: int = 40       # coarse pre-filter divisor


def get_threshold(ext: str) -> int:
    """Phase 7's YAML overlay swaps THIS function; do not inline
    ``DEFAULT_SIZE_CAPS`` elsewhere."""
    return DEFAULT_SIZE_CAPS.get(ext, DEFAULT_SIZE_CAPS["default"])


def _count_lines(file_path: Path) -> int:
    """Count lines without loading the whole file into memory.

    Returns 0 on read failure (OSError) -- the caller treats 0 as
    'no overage' and skips emission.
    """
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    repo_path = Path(repo_path).resolve()
    findings: list[Finding] = []

    for file_path, meta in repo_index.items():
        threshold = get_threshold(meta.ext)
        # Pattern 6 coarse pre-filter -- skips ~99% of files on typical
        # repos without ever opening them for content read.
        if meta.size_bytes < threshold * BYTES_PER_LINE_FLOOR:
            continue
        line_count = _count_lines(file_path)
        if line_count <= threshold:
            continue
        try:
            rel = str(file_path.relative_to(repo_path))
        except ValueError:
            continue
        overage = line_count - threshold
        findings.append(Finding(
            dimension="quality",
            severity="minor",
            evidence_type="static",
            confidence="high",
            source_tool="in-process",
            source_collector="file_size_cap",
            file=rel,
            evidence=Evidence(
                tool="in-process",
                parsed_value={
                    "file": rel,
                    "line_count": line_count,
                    "threshold": threshold,
                    "overage": overage,
                    "ext": meta.ext,
                },
            ),
            recommendation=(
                f"split — {line_count} lines exceeds the "
                f"{threshold}-line cap for {meta.ext}"
            ),
        ))

    return CollectorResult(
        findings=findings,
        status="ok",
        source_collector="file_size_cap",
        dimension="quality",
        scanned_paths=[str(repo_path)],
    )
