"""COLL-04 — README / LICENSE / CHANGELOG / docs/ presence findings.

When to use: when narrating the `quality` dimension's documentation
sub-topic — discussing whether the repo has a README, LICENSE,
CHANGELOG, or docs/ directory. Each Finding's parsed_value names the
missing artifact when absent.

When NOT to use: for docstring coverage in code (no v1 tool — narrate
honestly), for external docs (no v1 tool), or for any other
documentation quality signal beyond presence.
"""
# Implementation notes (preserved from the original module docstring):
# Each target emits a Finding regardless of presence -- absent docs are
#   explicit ``present=False`` rows, not silently omitted (SAFE-08).
# All Findings carry ``presence_only=True``; the schema validator caps
#   severity at ``info`` (SAFE-03 / D-19).
# Root-level file matching is case-insensitive name-prefix against the
#   ``RepoIndex`` keys whose ``.parent`` resolves to the repo root. The
#   ``docs/`` check goes directly to ``Path.is_dir`` so it picks up an
#   empty ``docs/`` directory even when the walker hasn't indexed files.
from __future__ import annotations
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.finding import Evidence, Finding


_TARGETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("README", ("README",)),
    ("LICENSE", ("LICENSE", "LICENCE")),       # British spelling tolerated
    ("CHANGELOG", ("CHANGELOG",)),
)


def _find_root_file(
    repo_path: Path, repo_index: dict, prefixes: tuple[str, ...]
) -> bool:
    """Case-insensitive name-prefix match against files whose .parent == repo_path."""
    for p in repo_index.keys():
        try:
            if p.parent.resolve() != repo_path:
                continue
        except (OSError, AttributeError):
            continue
        name_upper = p.name.upper()
        if any(name_upper.startswith(pref) for pref in prefixes):
            return True
    return False


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    repo_path = Path(repo_path).resolve()
    findings: list[Finding] = []

    for label, prefixes in _TARGETS:
        present = _find_root_file(repo_path, repo_index, prefixes)
        findings.append(Finding(
            dimension="quality",
            severity="info",
            evidence_type="static",
            confidence="high",
            source_tool="in-process",
            source_collector="doc_presence",
            evidence=Evidence(
                tool="in-process",
                parsed_value={
                    "doc": label,
                    "present": present,
                    "presence_only": True,           # SAFE-03 ceiling
                },
            ),
            recommendation="" if present else f"add {label}",
        ))

    # docs/ directory check (separate from repo_index -- sees the directory
    # itself even when it's empty enough to have no indexed files).
    docs_present = (repo_path / "docs").is_dir()
    findings.append(Finding(
        dimension="quality",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="in-process",
        source_collector="doc_presence",
        evidence=Evidence(
            tool="in-process",
            parsed_value={
                "doc": "docs/",
                "present": docs_present,
                "presence_only": True,
            },
        ),
        recommendation="" if docs_present else "add docs/",
    ))

    return CollectorResult(
        findings=findings,
        status="ok",
        source_collector="doc_presence",
        dimension="quality",
        scanned_paths=[str(repo_path)],
    )
