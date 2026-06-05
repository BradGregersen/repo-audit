"""Fuzz-lane DETECTION + candidate-surface heuristic (FUZZ-01, Plan 16-03).

READ-ONLY. This module never invokes a tool, never shells out, never writes to
the target repo. It answers three questions by reading the repo's files:

  * :func:`fastcheck_present` — does the repo declare ``fast-check``? fast-check
    is a PROPERTY harness that runs INSIDE the project's own Jest/Vitest test
    run; it has NO standalone CLI. So the lane only records its PRESENCE as a
    signal and NEVER invokes fast-check on its own (Pitfall 4 / Assumption A1 —
    fast-check is DETECT-ONLY this phase). There is deliberately no run path here.

  * :func:`native_targets` — does the repo ship a native libFuzzer-based target?
    A ``fuzz_*.py`` / ``*_fuzz.py`` calling ``atheris.Setup`` (Python/atheris) or
    a ``*FuzzTest`` / ``@FuzzTest`` JVM class (Java/jazzer). These are the only
    suites the lane RUNS — and only under the opt-in ``--fuzz`` flag + a budget
    (see ``__init__.run_fuzz``). Each hit records ``engine`` + ``path``.

  * :func:`candidate_surfaces` — the one genuinely new read-only scanner (no
    existing analog): a lightweight heuristic over exported function names +
    filenames matching high-value input-boundary patterns (parse / deserialize /
    decode / loads / unmarshal / fromBytes …). For each such surface NOT already
    covered by a detected fuzz target it emits ONE INFORMATIONAL candidate
    Finding phrased as a SIGNAL ("consider fuzzing X") — NEVER a verdict and
    NEVER a generated fuzz target (D-16-06). The Finding shape mirrors
    ``stryker_json.weak_test_signal``: ``confidence='candidate'``,
    ``severity='info'``, ``evidence_type='static'``, cross-linkable.

Every function is best-effort and never raises on a malformed / unreadable file
(a hostile or broken target repo must not break a scan).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "fuzz"
_DIMENSION = "test_integrity"

# Cap how much of any single file we read for the content probes — a bounded
# read keeps a pathological huge file from dominating a scan (the file-size
# concerns are someone else's collector; here we only need the head).
_MAX_READ_BYTES = 200_000
# Cap how many files we walk for the candidate heuristic — read-only, but
# bounded so an enormous repo does not turn detection into a full crawl.
_MAX_CANDIDATE_FILES = 5_000

# Directories we never descend into for the native-target / candidate scans
# (vendored deps, build output, VCS internals — never our surfaces).
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "build",
        "dist",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        "vendor",
    }
)

FuzzEngine = Literal["atheris", "jazzer"]


@dataclass(frozen=True)
class FuzzTarget:
    """A detected native fuzz target (read-only detection result).

    ``engine`` is the libFuzzer-based engine (atheris for Python, jazzer for the
    JVM); ``path`` is the repo-relative file that declares the target. The
    envelope runs these — and ONLY these — under the opt-in ``--fuzz`` flag.
    """

    engine: FuzzEngine
    path: str


# --- fast-check presence (DETECT-ONLY) -------------------------------------

# package.json dependency sections fast-check can be declared in.
_DEP_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


def _read_text_bounded(path: Path) -> str:
    """Read up to ``_MAX_READ_BYTES`` of ``path`` as text; "" on any failure."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(_MAX_READ_BYTES)
    except OSError:
        return ""


def fastcheck_present(repo_path: Path) -> bool:
    """True when the repo declares ``fast-check`` in any package.json dep section.

    READ-ONLY and bounded: parses ``package.json`` at the repo root. fast-check
    has no standalone CLI — its presence is a SIGNAL the property suite runs
    inside the normal test run (Pitfall 4 / A1). There is intentionally NO run
    path. Never raises (a malformed package.json → False).
    """
    pkg = Path(repo_path) / "package.json"
    if not pkg.is_file():
        return False
    raw = _read_text_bounded(pkg)
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    for section in _DEP_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict) and "fast-check" in deps:
            return True
    return False


# --- native target detection -----------------------------------------------

# atheris (Python): a fuzz_*.py / *_fuzz.py that calls atheris.Setup(...).
_PY_FUZZ_NAME = re.compile(r"(?:^fuzz_.*\.py$)|(?:.*_fuzz\.py$)")
_ATHERIS_SETUP = re.compile(r"\batheris\s*\.\s*Setup\b")
# jazzer (JVM): a *FuzzTest class or an @FuzzTest-annotated method.
_JVM_FUZZ_NAME = re.compile(r".*FuzzTest\.(?:java|kt)$")
_JVM_FUZZTEST_ANN = re.compile(r"@FuzzTest\b")
_JVM_FUZZTEST_CLASS = re.compile(r"\bclass\s+\w*FuzzTest\b")


def _iter_repo_files(repo_path: Path):
    """Yield files under ``repo_path`` (bounded, skipping vendored/build dirs)."""
    count = 0
    root = Path(repo_path)
    try:
        walker = root.rglob("*")
    except OSError:
        return
    for p in walker:
        # Skip anything inside a vendored/build/VCS directory.
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        yield p
        count += 1
        if count >= _MAX_CANDIDATE_FILES:
            return


def native_targets(repo_path: Path) -> list[FuzzTarget]:
    """Find native libFuzzer-based fuzz targets (atheris / jazzer). READ-ONLY.

    A Python target = a ``fuzz_*.py`` / ``*_fuzz.py`` whose content calls
    ``atheris.Setup``. A JVM target = a ``*FuzzTest.(java|kt)`` or any file
    declaring an ``@FuzzTest`` method / a ``*FuzzTest`` class. Returns each as a
    :class:`FuzzTarget` (engine + repo-relative path). Never raises.
    """
    root = Path(repo_path)
    targets: list[FuzzTarget] = []
    for p in _iter_repo_files(root):
        name = p.name
        rel = _rel(p, root)
        if _PY_FUZZ_NAME.match(name):
            content = _read_text_bounded(p)
            if _ATHERIS_SETUP.search(content):
                targets.append(FuzzTarget(engine="atheris", path=rel))
            continue
        if name.endswith((".java", ".kt")):
            content = _read_text_bounded(p)
            if (
                _JVM_FUZZ_NAME.match(name)
                or _JVM_FUZZTEST_ANN.search(content)
                or _JVM_FUZZTEST_CLASS.search(content)
            ):
                targets.append(FuzzTarget(engine="jazzer", path=rel))
    return targets


def _rel(path: Path, root: Path) -> str:
    """Best-effort repo-relative POSIX path (falls back to the file name)."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


# --- candidate-surface heuristic (D-16-06) ---------------------------------

# High-value input-boundary verbs. A symbol or filename matching one of these
# is a fuzzable surface — untrusted bytes flow through a parser/decoder.
_HIGH_VALUE: tuple[str, ...] = (
    "parse",
    "deserialize",
    "decode",
    "frombytes",
    "loads",
    "unmarshal",
    "fromjson",
    "readframe",
)

# Source files we scan for exported parser-like symbols.
_SOURCE_EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".kt", ".go", ".rs")

# Exported / top-level function declarations across the supported languages.
# (best-effort regex — detection is a SIGNAL, not a guarantee.)
_FUNC_DECL = re.compile(
    r"""
    (?:
        (?:export\s+)?(?:async\s+)?function\s+(?P<jsfn>\w+)   # JS/TS function foo
      | (?:export\s+)?const\s+(?P<jsconst>\w+)\s*=\s*(?:async\s*)?\(  # export const foo = (
      | def\s+(?P<pyfn>\w+)\s*\(                              # python def foo(
      | func\s+(?P<gofn>\w+)\s*\(                             # go func foo(
      | (?:pub\s+)?fn\s+(?P<rsfn>\w+)\s*\(                    # rust fn foo(
    )
    """,
    re.VERBOSE,
)


def _matches_high_value(name: str) -> bool:
    """True when a symbol/filename (lowercased) contains a high-value verb."""
    low = name.lower()
    return any(verb in low for verb in _HIGH_VALUE)


def candidate_surfaces(
    repo_path: Path, fuzzed_paths: frozenset[str] | set[str] | None = None
) -> list[Finding]:
    """Emit ONE candidate-SIGNAL Finding per un-fuzzed high-value surface.

    READ-ONLY heuristic: walk source files, find exported/top-level function
    symbols whose name (or whose filename) matches a high-value input-boundary
    verb (parse/deserialize/decode/loads/unmarshal/…). For each such surface NOT
    already covered by a detected fuzz target (``fuzzed_paths``) emit ONE
    informational Finding phrased as a SIGNAL ("consider fuzzing <symbol>"),
    ``confidence='candidate'``, ``severity='info'``, ``evidence_type='static'``.

    NEVER a verdict, NEVER a generated fuzz target, NEVER writes a file. Mirrors
    ``stryker_json.weak_test_signal``'s signal-not-verdict shape (D-16-06). Never
    raises.
    """
    root = Path(repo_path)
    fuzzed = set(fuzzed_paths or ())
    findings: list[Finding] = []
    seen: set[str] = set()  # de-dupe (file, symbol) so one surface = one signal

    for p in _iter_repo_files(root):
        if p.suffix not in _SOURCE_EXTS:
            continue
        rel = _rel(p, root)
        if rel in fuzzed:
            continue  # already covered by a detected fuzz target
        content = _read_text_bounded(p)
        if not content:
            continue

        filename_signal = _matches_high_value(p.stem)
        for m in _FUNC_DECL.finditer(content):
            symbol = (
                m.group("jsfn")
                or m.group("jsconst")
                or m.group("pyfn")
                or m.group("gofn")
                or m.group("rsfn")
            )
            if not symbol:
                continue
            if symbol.startswith("_"):
                continue  # private/non-exported convention — not a surface
            if not (_matches_high_value(symbol) or filename_signal):
                continue
            key = f"{rel}::{symbol}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(_candidate_finding(rel, symbol))

    return findings


def _candidate_finding(rel_path: str, symbol: str) -> Finding:
    """Build ONE candidate-surface SIGNAL Finding (never a verdict/target)."""
    return Finding(
        dimension=_DIMENSION,
        severity="info",  # SAFE: a hint, never a verdict
        evidence_type="static",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="fuzz_candidate",
        rule_id="unfuzzed_surface",
        file=rel_path,
        recommendation=(
            f"Consider fuzzing `{symbol}` in {rel_path} — it looks like a "
            "high-value input-boundary surface (a parser/decoder/deserializer) "
            "with no detected fuzz target. A signal to consider, not a verdict; "
            "the lane never authors a fuzz target for you."
        ),
        evidence=Evidence(
            tool="fuzz-detect",
            output_snippet=(
                f"un-fuzzed high-value surface: {symbol} ({rel_path}) — "
                "candidate signal"
            ),
            parsed_value={
                "symbol": symbol,
                "surface_path": rel_path,
                "signal": "consider_fuzzing",
            },
        ),
    )


__all__ = [
    "FuzzTarget",
    "FuzzEngine",
    "fastcheck_present",
    "native_targets",
    "candidate_surfaces",
]
