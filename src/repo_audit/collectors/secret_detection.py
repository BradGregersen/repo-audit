"""COLL-03 — working-tree secret-grep findings (gitleaks + entropy backstop).

When to use: when narrating the `security` dimension's secrets sub-topic
— discussing whether high-entropy or known-pattern secrets appear in the
working tree. Findings carry `evidence_type: heuristic` and
`confidence: candidate` at v1; values are ALWAYS rendered `[REDACTED:N]`
(raw secret values are never present in the Finding by schema design).

When NOT to use: for ESLint security/* rules (use get_eslint_lint), for
type-system soundness (use get_tsc_diagnostics), or for runtime auth
misconfig (no v1 tool — narrate the gap honestly).
"""
# Implementation notes (preserved from the original module docstring):
# Mirrors Phase 1's render/secret_lint.scan_with_gitleaks pattern but at
#   the collector boundary instead of the renderer chokepoint. The
#   renderer's secret-lint (Phase 1 D-07) remains the final structural
#   guard -- this collector populates Finding rows; the chokepoint catches
#   any value that accidentally escapes redaction (defense in depth, C13).
# Reuses Phase 1 detection modules (NO duplication): scan_with_entropy
#   (pure-Python entropy + known-pattern backstop); scan_with_gitleaks
#   (subprocess, graceful degrade when gitleaks absent);
#   scan_with_known_patterns (invoked INTERNALLY by scan_with_entropy);
#   SecretHit (dataclass with line + rule_id + redacted_len).
# Finding shape (RESEARCH.md Pattern 3): output_snippet =
#   f'{rule_id} [REDACTED:{redacted_len}] at line {line}' -- NEVER the raw
#   value; parsed_value = {'rule_id': str, 'redacted_len': int} -- NEVER
#   {value, secret, match, raw, original, token}.
# Pitfall 7: docs/state-reports/ excluded -- yesterday's report's
#   [REDACTED:N] placeholders would otherwise be re-flagged by entropy.
# Pitfall 8: gitleaks subprocess uses Phase 1's 30s timeout (already
#   enforced inside scan_with_gitleaks; do NOT duplicate the call).
# SAFE-06 reminder: severity='major' but confidence='candidate' -- the
#   candidate confidence-rung blocks SAFE-01's critical+static caveat
#   requirement and signals to Phase 4 that corroboration is required
#   before promotion. The renderer/agent never auto-promotes a candidate.
from __future__ import annotations

import shutil
from pathlib import Path

from ruamel.yaml import YAML

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.render.secret_lint import (
    SecretHit,
    scan_with_entropy,
    scan_with_gitleaks,
    scan_with_known_patterns,
)
from repo_audit.schema.finding import Evidence, Finding


# Resolved once per process: amortizes shutil.which cost across fleet sweeps
# and matches Phase 1's secret_lint module-load discovery pattern.
GITLEAKS_AVAILABLE: bool = shutil.which("gitleaks") is not None

# Opt-in config key (default OFF). The Shannon-entropy backstop produced a
# VERIFIED 100% false-positive rate on the user's own repos (9,661 noise / 0
# real on adapt), all rendered severity=major -- faking the security dimension
# and overflowing the agent's finding-inspection budget. Known-pattern +
# gitleaks stay always-on (they cover real accidentally-committed keys);
# the entropy half is re-enabled per target repo via .repo-audit.yaml.
# No global pydantic config model exists yet (Phase 7 overlay); this scoped
# ruamel.yaml safe-load mirrors the established adapter.yaml / faithfulness.yaml
# loaders rather than inventing a parallel config system (260530-gm9).
_CONFIG_FILENAME = ".repo-audit.yaml"


def _entropy_backstop_enabled(repo_path: Path) -> bool:
    """Return True only when secret_detection.entropy_backstop is set true in
    the target repo's .repo-audit.yaml. Default False; never raises.

    Fail-safe OFF: a missing file, an absent key, a non-dict shape, or a
    malformed/unreadable overlay all yield False so a hostile or broken config
    can neither re-enable the noisy heuristic by accident nor break the scan.
    """
    config_path = repo_path / _CONFIG_FILENAME
    if not config_path.is_file():
        return False
    try:
        yaml = YAML(typ="safe")  # T-gm9-01: refuses !!python/object, no code exec
        with config_path.open("r", encoding="utf-8") as fh:
            cfg = yaml.load(fh) or {}
    except Exception:
        # T-gm9-02: malformed/unreadable overlay must not break the scan.
        return False
    if not isinstance(cfg, dict):
        return False
    section = cfg.get("secret_detection")
    if not isinstance(section, dict):
        return False
    return bool(section.get("entropy_backstop", False))

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

    # 260530-gm9: resolve the opt-in flag ONCE before the file loop. Default OFF.
    entropy_backstop_on = _entropy_backstop_enabled(repo_path)

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
        # 260530-gm9: Always-on, low-FP named-rule layer (AKIA/ghp_/sk_live_/...).
        # Called DIRECTLY so it survives independent of the entropy flag
        # (CONTEXT: known-pattern detection is ALWAYS ON).
        hits.extend(scan_with_known_patterns(text))
        # OPT-IN heuristic (default OFF). scan_with_entropy() composes
        # scan_with_known_patterns at its tail, so to avoid double-counting the
        # named-rule hits above we keep ONLY its entropy-backstop hits here.
        if entropy_backstop_on:
            hits.extend(
                h for h in scan_with_entropy(text) if h.rule_id == "entropy-backstop"
            )

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
