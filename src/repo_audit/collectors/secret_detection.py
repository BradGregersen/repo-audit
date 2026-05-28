"""COLL-03: working-tree secret detection per D-35.

Mirrors Phase 1's render/secret_lint.scan_with_gitleaks pattern but at
the collector boundary instead of the renderer chokepoint. The renderer's
secret-lint (Phase 1 D-07) remains the final structural guard -- this
collector populates Finding rows; the chokepoint catches any value that
accidentally escapes redaction (defense in depth, per C13).

Reuses Phase 1 detection modules (NO duplication):
    - scan_with_entropy        -- pure-Python entropy + known-pattern backstop
    - scan_with_gitleaks       -- subprocess (graceful degrade when gitleaks absent)
    - scan_with_known_patterns -- invoked INTERNALLY by scan_with_entropy
    - SecretHit                -- dataclass with line + rule_id + redacted_len

Finding shape (per RESEARCH.md Pattern 3):
    output_snippet = f'{rule_id} [REDACTED:{redacted_len}] at line {line}'
        -- NEVER the raw value
    parsed_value = {'rule_id': str, 'redacted_len': int}
        -- NEVER {value, secret, match, raw, original, token}

Pitfall 7: docs/state-reports/ excluded -- yesterday's report's [REDACTED:N]
placeholders would otherwise be re-flagged by entropy.
Pitfall 8: gitleaks subprocess uses Phase 1's 30s timeout (already
enforced inside scan_with_gitleaks; do NOT duplicate the subprocess call).

SAFE-06 reminder: severity='major' but confidence='candidate' -- the
candidate confidence-rung blocks SAFE-01's critical+static caveat
requirement and signals to Phase 4 that corroboration is required before
promotion. The renderer/agent never auto-promotes a candidate secret.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.render.secret_lint import (
    SecretHit,
    scan_with_entropy,
    scan_with_gitleaks,
)
from repo_audit.schema.finding import Evidence, Finding


# Resolved once per process: amortizes shutil.which cost across fleet sweeps
# and matches Phase 1's secret_lint module-load discovery pattern.
GITLEAKS_AVAILABLE: bool = shutil.which("gitleaks") is not None

# Per-file content-read DoS guard (matches Phase 1 secret_lint posture).
# Files larger than this are skipped before any read -- gitleaks subprocess
# pipe-buffer deadlock (Pitfall 8) becomes the primary concern above this
# threshold; the in-process backstop also degrades to O(n) per file at this
# size. 1MB is well above typical config/source files.
MAX_FILE_BYTES: int = 1_000_000

# Text extensions we attempt to scan. Anything else is treated as likely-binary
# and skipped before the read syscall. The strict UTF-8 decode below is the
# real filter; this just prunes obvious binaries before paying for read_text().
_TEXT_EXTS: frozenset[str] = frozenset({
    ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".kt", ".kts", ".java", ".go", ".rs", ".cs", ".cpp", ".cc", ".c",
    ".h", ".hpp", ".hh", ".m", ".mm", ".swift", ".rb", ".php", ".pl",
    ".md", ".rst", ".txt", ".json", ".jsonc", ".yml", ".yaml", ".toml",
    ".sh", ".bash", ".zsh", ".fish", ".env", ".ini", ".cfg", ".conf",
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".sql", ".graphql", ".gql", ".proto", ".tf", ".tfvars", ".xml", ".svg",
})


def _looks_text(file_path: Path, ext: str) -> bool:
    """Heuristic: known text ext, OR extension-less but conventionally textual.

    The strict UTF-8 decode in run() is the real filter; this just prunes
    obvious binaries before paying the read_text() syscall.
    """
    if ext in _TEXT_EXTS:
        return True
    # Special-case extension-less files like Dockerfile, Makefile, LICENSE,
    # README, AUTHORS, CHANGELOG. We require the first character be a letter
    # so a binary file named ".bin-blob" doesn't slip through.
    return ext == "" and file_path.name[:1].isalpha()


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    """COLL-03 entry point.

    Iterates the pre-built RepoIndex (Plan 02-01a) for text files, scans
    each with gitleaks (if on PATH) AND the in-process backstop, and emits
    one Finding per detected hit with the raw value structurally absent
    from both output_snippet and parsed_value.

    Args:
        repo_path: Path to the target repo root.
        repo_index: dict[Path, FileMeta] from build_repo_index().

    Returns:
        CollectorResult with status='ok' when gitleaks is available;
        status='partial' otherwise (notes documents the precision drop).
    """
    repo_path = Path(repo_path).resolve()
    state_report_prefix = repo_path / "docs" / "state-reports"

    findings: list[Finding] = []
    scanned_files = 0

    for file_path, meta in repo_index.items():
        # Pitfall 7 -- defensive double-check; the walker already excludes
        # docs/state-reports/ at the repo root (Plan 02-01a). Belt-and-
        # suspenders in case a future caller hands us a hand-built index.
        try:
            if state_report_prefix in file_path.parents:
                continue
        except (AttributeError, ValueError):
            # file_path may not behave like a Path under some serialization
            # paths; skip rather than crash.
            continue

        # Threat T-02-04-03: skip large files before any read.
        if meta.size_bytes > MAX_FILE_BYTES:
            continue
        # Prune obvious binaries before paying for read_text().
        if not _looks_text(file_path, meta.ext):
            continue
        # Threat T-02-04-05: relative_to() validates the file lives under
        # repo_path. If it doesn't (path-traversal attempt), ValueError
        # falls through to the bare except below and the file is skipped.
        try:
            text = file_path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        scanned_files += 1

        hits: list[SecretHit] = []
        if GITLEAKS_AVAILABLE:
            hits.extend(scan_with_gitleaks(text))
        # scan_with_entropy internally composes scan_with_known_patterns
        # (see secret_lint.py docstring); invoking both would double-count
        # per Phase 1 secret_lint.lint_buffer's comment.
        hits.extend(scan_with_entropy(text))

        for hit in hits:
            try:
                rel = file_path.relative_to(repo_path)
            except ValueError:
                # Path traversal attempt (T-02-04-05) -- structurally cannot
                # happen if the walker did its job, but defend in depth.
                continue
            # C13 / T-02-04-01: output_snippet is the HARD-CODED redacted
            # template. The raw value never enters this f-string -- only
            # rule_id (a label like 'aws-access-key-id') and the length.
            findings.append(Finding(
                dimension="security",
                severity="major",                  # SAFE-06: candidate caps at major
                confidence="candidate",            # SAFE-06: requires corroboration
                evidence_type="heuristic",         # SAFE-01: not a runtime probe
                source_tool="gitleaks" if GITLEAKS_AVAILABLE else "in-process",
                source_collector="secret_detection",
                file=str(rel),
                line=hit.line,
                rule_id=hit.rule_id,
                recommendation=(
                    "investigate: this is a candidate heuristic match; "
                    "verify with the secret owner and rotate if real"
                ),
                evidence=Evidence(
                    tool="gitleaks" if GITLEAKS_AVAILABLE else "in-process",
                    output_snippet=(
                        f"{hit.rule_id} [REDACTED:{hit.redacted_len}] "
                        f"at line {hit.line}"
                    ),
                    parsed_value={
                        # SCH-08 + D-35: ONLY these two keys. NEVER 'value',
                        # 'secret', 'match', 'raw', 'original', or 'token'.
                        "rule_id": hit.rule_id,
                        "redacted_len": hit.redacted_len,
                    },
                    line_range=(hit.line, hit.line),
                ),
            ))

    status = "ok" if GITLEAKS_AVAILABLE else "partial"
    notes = (
        ""
        if GITLEAKS_AVAILABLE
        else "gitleaks not on PATH -- entropy + known-pattern backstop only"
    )

    return CollectorResult(
        findings=findings,
        status=status,
        notes=notes,
        source_collector="secret_detection",
        dimension="security",
        scanned_paths=[f"{scanned_files} files"],
    )
