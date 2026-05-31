"""COLL-05 — TODO/FIXME/HACK marker counts across the working tree.

When to use: when narrating the `process` dimension's backlog sub-topic
— discussing TODO / FIXME / HACK marker density, hotspot files, or
trend if the prior sidecar reports them. Each Finding carries the
file:line and the marker word.

When NOT to use: for general code quality (use get_eslint_lint), for
dead code (use get_knip_dead_code), or for type errors (use
get_tsc_diagnostics).
"""
# Implementation notes (preserved from the original module docstring):
# Regex (Claude's-Discretion in 02-CONTEXT.md): \\b(TODO|FIXME|HACK|XXX)\\b
#   case-insensitive. Word boundaries ensure 'TODOed' / 'XXXth' /
#   'shacked' do NOT match. The collector does NOT lex per-language;
#   matches inside comments and string literals fire alike, the correct
#   universal posture (Phase 6 Python/Kotlin adapters may layer a more
#   precise scan via ruff/detekt later).
# Performance bounds: skip files > 1 MB (MAX_FILE_BYTES) to avoid
#   unbounded reads on minified bundles, lockfiles, large CSV; skip files
#   whose extension is not in _TEXT_EXTS (binary heuristic; extensionless
#   files starting with an alphanumeric char are considered text, covering
#   README/LICENSE/Makefile); errors='ignore' on the streaming read so
#   UTF-8 noise is dropped rather than raising (Pattern 5, 02-RESEARCH.md).
# Note: todo_markers does NOT import _TEXT_EXTS from secret_detection even
#   though both share the heuristic. Cross-collector imports create cycles
#   through collectors/__init__.py and couple two collectors that should
#   remain independent (per 02-05-PLAN.md Task 2 read_first).
from __future__ import annotations
import re
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors._budget import DeadlineGuard
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.finding import Evidence, Finding


TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)

MAX_FILE_BYTES: int = 1_000_000
SNIPPET_TRIM: int = 120

_TEXT_EXTS: frozenset[str] = frozenset({
    ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".kt", ".kts", ".java",
    ".go", ".rs", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp",
    ".md", ".rst", ".txt", ".sh", ".bash", ".zsh", ".fish",
    ".html", ".css", ".scss", ".sql", ".graphql", ".proto",
})


def _looks_text(file_path: Path, ext: str) -> bool:
    """True when ext is in ``_TEXT_EXTS`` or it's an extensionless name
    starting with an alphabetic char (README, LICENSE, Makefile, etc.)."""
    return ext in _TEXT_EXTS or (ext == "" and file_path.name[:1].isalpha())


@register_collector
def run(
    repo_path: Path,
    repo_index: dict,
    *,
    deadline: float | None = None,
) -> CollectorResult:
    """05.1-gap: ``deadline`` is the shared ``time.perf_counter`` scan deadline.

    The per-file content read previously ran unbounded (~9 s on the 40 GB adapt;
    pathological on a larger tree). The loop now polls the deadline once per N
    files and stops early when it is reached, self-reporting ``status='timeout'``
    so the scope ledger discloses that not every file was scanned (SAFE-08).
    """
    repo_path = Path(repo_path).resolve()
    findings: list[Finding] = []
    guard = DeadlineGuard(deadline)
    deadline_hit = False
    scanned_files = 0

    for file_path, meta in repo_index.items():
        if guard.tick():
            deadline_hit = True
            break
        if meta.size_bytes > MAX_FILE_BYTES:
            continue
        if not _looks_text(file_path, meta.ext):
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned_files += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in TODO_RE.finditer(line):
                try:
                    rel = str(file_path.relative_to(repo_path))
                except ValueError:
                    continue
                snippet = line.strip()[:SNIPPET_TRIM]
                findings.append(Finding(
                    dimension="quality",
                    severity="info",
                    evidence_type="static",
                    confidence="high",
                    source_tool="in-process",
                    source_collector="todo_markers",
                    file=rel,
                    line=lineno,
                    rule_id=f"todo-{m.group(1).upper()}",
                    evidence=Evidence(
                        tool="in-process",
                        output_snippet=snippet,
                        parsed_value={
                            "marker": m.group(1).upper(),
                            "snippet": snippet,
                        },
                        line_range=(lineno, lineno),
                    ),
                ))

    return CollectorResult(
        findings=findings,
        status="timeout" if deadline_hit else "ok",
        notes=(
            f"scan time budget reached after {scanned_files} files; "
            "remaining files not scanned for TODO markers"
            if deadline_hit
            else ""
        ),
        source_collector="todo_markers",
        dimension="quality",
        scanned_paths=[str(repo_path)],
    )
