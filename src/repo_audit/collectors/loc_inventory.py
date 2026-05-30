"""COLL-02 — LOC by language + file inventory (via vendored scc binary).

When to use: when narrating the `quality` dimension's footprint sub-
topic — discussing total LOC, language mix, file count, or top-N largest
files. Each Finding's parsed_value carries the structured scc output;
use the leaf numbers (total_loc, by-language entries, top files).

When NOT to use: for type-checking errors (use get_tsc_diagnostics),
lint hits (use get_eslint_lint), dead-code candidates (use
get_knip_dead_code), or coverage (use get_lcov_coverage).
"""
# Implementation notes (preserved from the original module docstring):
# Runs ``scc -f json --no-cocomo <repo>`` against the vendored Go binary,
#   parses the JSON, strips the per-file ``Content`` field (Pitfall 1:
#   base64 file contents would inflate the sidecar 100x and trip the
#   entropy backstop in render/secret_lint.lint_buffer), and emits one
#   Finding per detected language plus one aggregate Finding listing the
#   top-N largest files.
# Subprocess hygiene (CLAUDE.md hard rules): shell=False; command as
#   list[str]; timeout=60 (TimeoutExpired -> status='timeout'); env
#   override NO_COLOR=1 FORCE_COLOR=0 TERM=dumb (PITFALLS.md m6); graceful
#   fallback on FileNotFoundError (binary missing for this platform).
# Pitfall 8 (subprocess buffer deadlock): mitigated by capture_output=True
#   + explicit timeout; large repos won't hang.
from __future__ import annotations

import json
import os
import platform
import subprocess
from importlib.resources import files
from pathlib import Path

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS


SCC_TIMEOUT_S: int = 60
TOP_N_FILES: int = 10
_OS_TAG = {"Linux": "linux", "Darwin": "macos"}
_CLEAN_ENV_OVERRIDES = {"NO_COLOR": "1", "FORCE_COLOR": "0", "TERM": "dumb"}


def _platform_tag() -> str:
    """Return '{os}-{arch}' for the vendor lookup. Raises on unsupported platforms."""
    system = platform.system()
    machine = platform.machine()
    os_tag = _OS_TAG.get(system)
    if os_tag is None:
        raise RuntimeError(f"unsupported platform: {system}")
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64"
    return f"{os_tag}-{arch}"


def _scc_binary_path() -> Path:
    """Resolve the vendored scc binary for this platform.

    Returns a Path; existence is verified by the caller. Uses
    importlib.resources so the wheel install works identically.
    """
    platform_tag = _platform_tag()
    base = files("repo_audit") / "vendor" / "scc" / platform_tag / "scc"
    return Path(str(base))


def _run_scc(repo_path: Path) -> list[dict]:
    """Invoke scc; return parsed list-of-language-dicts with Content stripped.

    Raises:
        FileNotFoundError -- binary missing for this platform (vendor gap)
        subprocess.TimeoutExpired -- scc exceeded SCC_TIMEOUT_S
        RuntimeError -- scc returned non-zero
        json.JSONDecodeError -- scc produced unparseable stdout
    """
    binary = _scc_binary_path()
    if not binary.exists():
        raise FileNotFoundError(
            f"vendored scc missing for this platform: {binary}"
        )
    env = {**os.environ, **_CLEAN_ENV_OVERRIDES}
    # SCAN-BOUND-01 (D-051-08) — scc --exclude-dir parity. Pass the
    # DEFAULT_SKIP_DIRS dir names (comma-separated) so scc cannot walk
    # vendored/build trees EVEN when the target repo has a poor .gitignore.
    # This is deterministic parity with the rest of the pipeline, independent
    # of the target's .gitignore. We do NOT pass --no-gitignore (that would
    # remove scc's existing default protection — RESEARCH / Don't-Hand-Roll).
    exclude_dirs = ",".join(sorted(DEFAULT_SKIP_DIRS))
    argv = [
        str(binary), "-f", "json", "--no-cocomo",
        "--exclude-dir", exclude_dirs,
        str(repo_path),
    ]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=SCC_TIMEOUT_S,
        shell=False,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"scc returncode={result.returncode}: {result.stderr[:500]}"
        )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, list):
        raise RuntimeError(f"scc JSON not a list; got {type(parsed).__name__}")
    # Pitfall 1: strip base64 Content field BEFORE Finding construction.
    for lang in parsed:
        if not isinstance(lang, dict):
            continue
        for f in lang.get("Files", []) or []:
            if isinstance(f, dict):
                f.pop("Content", None)
    return parsed


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    # Resolve platform; Windows raises here.
    try:
        platform_tag = _platform_tag()
    except RuntimeError as exc:
        return CollectorResult(
            status="unavailable",
            notes=str(exc),
            source_collector="loc_inventory",
            dimension="quality",
            scanned_paths=[str(repo_path)],
        )

    # Run scc.
    try:
        parsed = _run_scc(repo_path)
    except FileNotFoundError as exc:
        return CollectorResult(
            status="unavailable",
            notes=f"vendored scc missing for {platform_tag}: {exc}",
            source_collector="loc_inventory",
            dimension="quality",
            scanned_paths=[str(repo_path)],
        )
    except subprocess.TimeoutExpired:
        return CollectorResult(
            status="timeout",
            notes=f"scc timed out after {SCC_TIMEOUT_S}s",
            source_collector="loc_inventory",
            dimension="quality",
            scanned_paths=[str(repo_path)],
        )
    except (RuntimeError, json.JSONDecodeError) as exc:
        return CollectorResult(
            status="unavailable",
            notes=f"scc parse error: {type(exc).__name__}: {exc}",
            source_collector="loc_inventory",
            dimension="quality",
            scanned_paths=[str(repo_path)],
        )

    # Build per-language Findings.
    findings: list[Finding] = []
    total_lines = 0
    all_files: list[tuple[int, str]] = []     # (lines, filename) tuples for top-N

    for lang in parsed:
        name = lang.get("Name", "Unknown")
        lines = int(lang.get("Lines", 0))
        code = int(lang.get("Code", 0))
        comment = int(lang.get("Comment", 0))
        blank = int(lang.get("Blank", 0))
        file_count = int(lang.get("Count", 0))
        complexity = int(lang.get("Complexity", 0))
        total_lines += lines

        findings.append(Finding(
            dimension="quality",
            severity="info",
            evidence_type="static",
            confidence="high",
            source_tool="scc",
            source_collector="loc_inventory",
            evidence=Evidence(
                tool="scc",
                parsed_value={
                    "language": name,
                    "files": file_count,
                    "lines": lines,
                    "code": code,
                    "comment": comment,
                    "blank": blank,
                    "complexity": complexity,
                },
            ),
            recommendation="",
        ))

        # Collect per-file lines for the top-N aggregate finding.
        for f in lang.get("Files", []) or []:
            if isinstance(f, dict):
                all_files.append((int(f.get("Lines", 0)), str(f.get("Filename", ""))))

    # Aggregate top-N-largest finding.
    all_files.sort(key=lambda t: t[0], reverse=True)
    top_files = [
        {"file": fname, "lines": lc} for lc, fname in all_files[:TOP_N_FILES]
    ]
    findings.append(Finding(
        dimension="quality",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="scc",
        source_collector="loc_inventory",
        evidence=Evidence(
            tool="scc",
            parsed_value={
                "summary": "top-N largest files",
                "total_lines": total_lines,
                "top_files": top_files,
            },
        ),
        recommendation="",
    ))

    return CollectorResult(
        findings=findings,
        status="ok",
        source_collector="loc_inventory",
        dimension="quality",
        scanned_paths=[str(repo_path)],
    )
