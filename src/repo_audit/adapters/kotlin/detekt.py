"""KOT-01 — Kotlin/Android detekt collector (Plan 11-02, Wave 1).

``collect_detekt`` is the cross-stack Kotlin collection FUNCTION (NOT a per-stack
``@register_adapter`` entry — wiring is the Phase-11 integration plan's job). It
mirrors ``sast/semgrep.py::collect_semgrep`` in shape: a thin, never-raising
collector that resolves the JRE + the vendored detekt-cli jar, invokes detekt
through the single shared ``run_tool`` seam (FND-04), reads detekt's SARIF FILE,
routes it through the single ``sarif_to_findings`` path (FND-01), applies the
D-11-08 noise floor, and returns a :class:`KotlinResult` envelope.

The pipeline:

    1. resolve ``java`` (passed ``java_binary`` or ``resolve_tool("java", repo)``)
       — None → status='unavailable' (no JRE → KOT-01 unavailable, never raises).
    2. resolve the vendored ``detekt`` jar (passed ``detekt_jar`` or
       ``resolve_tool("detekt", repo)``) — None → status='unavailable'.
    3. Allocate a SARIF output FILE inside a ``scan_tempdir`` (Pitfall 4 — detekt
       writes SARIF to the FILE in ``--report sarif:<path>``, NOT stdout).
    4. If ``attempt_typed``: best-effort resolve the compile classpath via a
       throwaway-copy gradle build (D-11-07). On a resolved classpath, build the
       TYPED argv (``--classpath`` + ``--jvm-target 17``); otherwise the
       STANDALONE argv (the KOT-01 floor). ALWAYS pass
       ``--build-upon-default-config`` (Pitfall 1 — without it ALL rules are OFF
       and detekt produces an empty report).
    5. run_tool(...) — gate on the structural sentinels: TIMED_OUT → 'timeout';
       EXEC_FAILED → 'unavailable'.
    6. Gate on the SARIF FILE: detekt EXITS NON-ZERO when it finds issues
       (Pitfall 5), so a non-zero exit with a parseable SARIF file present is
       ``status='ok'`` WITH findings — NOT a failure. The gate is "does the SARIF
       parse", never the returncode. No SARIF / unparseable → 'unavailable'.
    7. sarif_to_findings(source_tool='detekt', default_dimension='quality') then
       apply_detekt_noise_floor (D-11-08).

``collect_detekt`` NEVER raises across its boundary: the parse + parser path is
wrapped so a malformed SARIF (T-11-02-05) folds into status='unavailable'.

NOTE: ``resolve_tool``, ``run_tool``, ``_read_sarif``, and
``try_resolve_classpath_via_throwaway_build`` are imported / defined as
MODULE-LEVEL names so the Wave-0 contract test can monkeypatch them (the
absent-binary path, the in-memory SARIF seam) without real file/JVM I/O.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.kotlin import KotlinResult
from repo_audit.adapters.kotlin.noise import apply_detekt_noise_floor
from repo_audit.adapters.kotlin.typed_build import (
    try_resolve_classpath_via_throwaway_build,
)
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

__all__ = ["collect_detekt", "run_detekt", "resolve_tool"]

# Default wall-clock bound for a single detekt run over a repo. run_tool does the
# SIGTERM→5s→SIGKILL escalation on expiry (T-11-02-03).
_DETEKT_TIMEOUT_SECONDS: float = 180.0

_SOURCE_TOOL = "detekt"
_DIMENSION = "quality"

# The JVM target detekt's type-resolution rules assume on the TYPED path. 17 is
# the current Android/Kotlin LTS baseline; only passed when a classpath resolved.
_JVM_TARGET = "17"


def _detekt_argv(
    java: Path,
    jar: Path,
    repo_path: Path,
    sarif_out: Path,
    classpath: Optional[str],
) -> list[str]:
    """Build the EXACT detekt argv (list[str], shell=False guard, T-11-02-01).

    ALWAYS includes ``--build-upon-default-config`` (Pitfall 1 — CRITICAL:
    without it detekt runs with ALL rules off and emits an empty report). detekt
    writes SARIF to the FILE named in ``--report sarif:<path>`` (Pitfall 4), NOT
    stdout, so ``sarif_out`` is the file the collector then reads. When a
    ``classpath`` is resolved (D-11-07 typed path), ``--classpath`` +
    ``--jvm-target`` activate type-resolution rules; otherwise the STANDALONE
    argv omits both (the always-safe KOT-01 floor). ``repo_path`` is a single
    argv element — never interpolated into a shell string.
    """
    argv: list[str] = [
        str(java),
        "-jar",
        str(jar),
        "--input",
        str(repo_path),
        "--build-upon-default-config",
        "--report",
        f"sarif:{sarif_out}",
    ]
    if classpath:
        argv += ["--classpath", classpath, "--jvm-target", _JVM_TARGET]
    return argv


def _read_sarif(path: Path) -> Optional[dict]:
    """Read + JSON-parse the detekt SARIF FILE, returning ``None`` on any failure.

    Module-level so the Wave-0 contract test can monkeypatch this seam at the
    in-memory fixture instead of doing real file I/O. detekt wrote the SARIF to
    ``path`` (Pitfall 4); a missing/unparseable file is the "no usable result"
    signal the caller maps to status='unavailable'.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _driver_version(sarif: dict) -> Optional[str]:
    """Pull ``runs[0].tool.driver.version`` from the detekt SARIF, guarding gaps.

    Mirrors ``semgrep._driver_version``. Returns ``None`` on any structural gap
    (no runs, no driver, non-string version).
    """
    try:
        runs = sarif.get("runs") or []
        driver = ((runs[0] or {}).get("tool") or {}).get("driver") or {}
        version = driver.get("version")
        return version if isinstance(version, str) else None
    except (IndexError, AttributeError, TypeError):
        return None


def collect_detekt(
    repo_path: Path,
    env: dict[str, str],
    *,
    detekt_jar: Optional[Path] = None,
    java_binary: Optional[Path] = None,
    attempt_typed: bool = True,
    timeout_seconds: float = _DETEKT_TIMEOUT_SECONDS,
) -> KotlinResult:
    """Run detekt over ``repo_path`` and return de-noised quality findings.

    Mirrors ``collect_semgrep``: typed-then-standalone argv,
    ``--build-upon-default-config`` always, a SARIF-FILE gate (not returncode),
    the shared parser + noise floor, never-raises.

    Args:
        repo_path: the Kotlin/Android repo to scan (detekt recurses from here).
        env: the child environment (cache-redirected by the caller).
        detekt_jar: explicit path to the vendored ``detekt-cli-all.jar``; when
            ``None`` it is resolved via ``resolve_tool("detekt", repo_path)``.
        java_binary: explicit path to the ``java`` launcher; when ``None`` it is
            resolved via ``resolve_tool("java", repo_path)``.
        attempt_typed: when True (default, D-11-07) try to resolve the compile
            classpath via a throwaway-copy gradle build for a deeper typed run;
            on ANY failure it falls back to standalone (the KOT-01 floor).
        timeout_seconds: hard wall-clock bound for the detekt run (default 180s).

    Returns:
        A :class:`KotlinResult`. ``status='ok'`` with quality-dimension
        static/candidate findings when the SARIF FILE parses (even on a non-zero
        detekt exit — Pitfall 5); ``status='unavailable'`` when java/jar is
        absent, exec-failed, or no parseable SARIF was produced;
        ``status='timeout'`` when the run exceeds ``timeout_seconds``. NEVER
        raises and NEVER hangs.
    """
    # (1) JRE: explicit launcher, else resolve. Absent → KOT-01 unavailable.
    java = java_binary or resolve_tool("java", repo_path)
    if java is None:
        return KotlinResult(status="unavailable", notes="java/JRE not found")

    # (2) Vendored detekt-cli jar.
    jar = detekt_jar or resolve_tool(_SOURCE_TOOL, repo_path)
    if jar is None:
        return KotlinResult(
            status="unavailable",
            notes="detekt-cli jar not found (vendor + node_modules + PATH miss)",
        )

    # (3) SARIF output FILE inside a per-call tempdir (Pitfall 4 — detekt writes
    #     the report to a file, not stdout; the tempdir keeps it out of the repo).
    with scan_tempdir() as tempdir:
        sarif_out = tempdir / "detekt.sarif"

        # (4) Best-effort typed classpath (D-11-07); None → standalone floor. The
        #     resolver is itself never-raising and returns None on any failure.
        classpath: Optional[str] = None
        if attempt_typed:
            classpath = try_resolve_classpath_via_throwaway_build(
                repo_path, env=env
            )

        # (5) Invoke detekt through the single shared run_tool seam.
        invocation = run_tool(
            _detekt_argv(Path(java), Path(jar), repo_path, sarif_out, classpath),
            env=env,
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # (6) run_tool structural sentinels first — these NEVER raise.
        if invocation.returncode == TIMED_OUT:
            return KotlinResult(
                status="timeout", notes=f"detekt exceeded {timeout_seconds:.0f}s"
            )
        if invocation.returncode == EXEC_FAILED:
            return KotlinResult(
                status="unavailable",
                notes=f"detekt could not be executed: {invocation.stderr}",
            )

        # (7) Gate on whether the SARIF FILE PARSES, NOT on returncode: detekt
        #     exits NON-ZERO when it finds issues (Pitfall 5), so a non-zero exit
        #     with a parseable SARIF file is findings, not a failure.
        sarif = _read_sarif(sarif_out)
        if not isinstance(sarif, dict):
            return KotlinResult(
                status="unavailable",
                notes="detekt produced no parseable SARIF file",
            )

        # SARIF is the SINGLE finding source (FND-01). The empty severity_map
        # selects the parser's faithful default level map; the parser stamps
        # evidence_type='static' + confidence='candidate' and enforces the SCH-04
        # candidate cap. detekt sets result.level per result (no
        # defaultConfiguration fallback fires).
        try:
            # Literal source_tool="detekt" / default_dimension="quality" at the
            # call site (the plan's acceptance contract); the module constants
            # _SOURCE_TOOL / _DIMENSION carry the same values for reuse elsewhere.
            findings = sarif_to_findings(
                sarif,
                source_tool="detekt",
                default_dimension="quality",
                severity_map={},
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return KotlinResult(
                status="unavailable",
                notes=f"detekt SARIF parse failed: {type(exc).__name__}: {exc}",
            )

        # D-11-08 noise floor: drop detekt.style.*/detekt.formatting.* + sub-floor
        # severities BEFORE any finding reaches the report.
        findings = apply_detekt_noise_floor(findings)

        mode = "typed" if classpath else "standalone"
        return KotlinResult(
            findings=findings,
            status="ok",
            scanner_version=_driver_version(sarif),
            notes=f"detekt ({mode}): {len(findings)} finding(s)",
        )


def run_detekt(
    repo_path: Path,
    *,
    attempt_typed: bool = True,
    timeout_seconds: float = _DETEKT_TIMEOUT_SECONDS,
) -> KotlinResult:
    """Convenience wrapper: run :func:`collect_detekt` with a default scan env.

    Builds a per-call cache-redirected scan env (mirrors ``run_semgrep``) so
    callers/tests that don't already have an env can invoke the collector
    directly — the ``-m integration`` live test uses this path. The Phase-11
    integration plan calls ``collect_detekt`` with the shared scan env instead.
    """
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        return collect_detekt(
            repo_path,
            env,
            attempt_typed=attempt_typed,
            timeout_seconds=timeout_seconds,
        )
