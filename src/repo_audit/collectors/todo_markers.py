"""COLL-05: TODO/FIXME/HACK/XXX marker grep over text files in RepoIndex.

Regex per Claude's-Discretion in 02-CONTEXT.md:

    \\b(TODO|FIXME|HACK|XXX)\\b   case-insensitive

The word boundaries (``\\b``) ensure 'TODOed' / 'XXXth' / 'shacked' do
NOT match. The collector does NOT lex per-language; matches inside
comments and string literals fire alike, which is the correct universal
posture (Phase 6 Python and Kotlin adapters may layer a more precise
scan via ruff/detekt later).

Performance bounds:

    * Skip files > 1 MB (``MAX_FILE_BYTES``) -- avoids unbounded reads
      on minified bundles, lockfiles, large CSV.
    * Skip files whose extension is not in ``_TEXT_EXTS`` (binary
      heuristic). Extensionless files starting with an alphanumeric
      character are considered text (covers README, LICENSE, Makefile).
    * ``read_text(errors='ignore')`` -- any UTF-8 noise is silently
      dropped rather than raising; consistent with Pattern 5 in
      02-RESEARCH.md.

Note: todo_markers does NOT import _TEXT_EXTS from secret_detection
even though both share the heuristic. Cross-collector imports create
cycles through collectors/__init__.py and couple two collectors that
should remain independent (per 02-05-PLAN.md Task 2 read_first).
"""
from __future__ import annotations
import re
from pathlib import Path

from repo_audit.collectors import register_collector
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
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    repo_path = Path(repo_path).resolve()
    findings: list[Finding] = []

    for file_path, meta in repo_index.items():
        if meta.size_bytes > MAX_FILE_BYTES:
            continue
        if not _looks_text(file_path, meta.ext):
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
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
        status="ok",
        source_collector="todo_markers",
        dimension="quality",
        scanned_paths=[str(repo_path)],
    )
