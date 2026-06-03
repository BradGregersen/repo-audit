"""EXP-01 — expo-doctor text-scrape collector (Plan 11-04, Wave 1).

``collect_expo_doctor`` is the cross-stack Expo health/config collector. It
mirrors ``sast/semgrep.py::collect_semgrep`` in shape — a thin, NEVER-raising
collector that resolves the tool, invokes it through the single shared
``run_tool`` seam (FND-04 / no direct ``subprocess``), and turns the result into
Findings.

WHY a text scrape (11-RESEARCH Pitfall 3, VERIFIED): expo-doctor is TEXT-ONLY —
there is NO ``--json`` / ``--sarif`` flag. So we parse via exit code + stable
line markers, with an aggregate-stdout-tail fallback when the line shape drifts
(RESEARCH Assumption A1). We never promise per-check granularity in the schema.

The pipeline:

    1. Resolve the binary. Prefer a target-local ``expo-doctor`` (resolve_tool),
       falling back to the documented ``npx expo-doctor`` argv. Preferring the
       ``node_modules``-resolved binary over an ``npx`` auto-download limits
       network egress (RESEARCH Security Domain, T-11-04-03).
    2. ``run_tool(argv, ...)`` — the single subprocess seam. Sentinel gate:
       ``TIMED_OUT`` (-2) → one ``timeout`` unavailable Finding; ``EXEC_FAILED``
       (-1) → one ``unavailable`` Finding (absent tool path, T-11-04-04 — argv is
       a ``list[str]`` through ``run_tool``, never a shell string).
    3. Exit 0 → ONE info-level ``quality`` Finding ("all checks passed").
    4. Non-zero → BEST-EFFORT per-check parse: one ``quality`` Finding per
       ``Issue:`` block; if no block matches (drift) → FALLBACK to ONE aggregate
       Finding carrying the bounded/redacted stdout tail (run through the
       secret-lint primitive ``refresh._redact_tail`` — T-11-04-02).
    5. Any unexpected exception degrades to one ``unavailable`` Finding — NEVER
       raises across the boundary.

``collect_expo_doctor`` returns a ``list[Finding]`` directly (the Wave-0 contract
test indexes the list). :func:`run_expo_doctor` is the convenience wrapper that
seeds a cache-redirected scan env and returns the :class:`ExpoResult` envelope
(the shape Plan 05's scan-runner step consumes).

NOTE: ``resolve_tool`` and ``run_tool`` are imported as module-level names so the
Wave-0 test can ``monkeypatch.setattr(doctor, "resolve_tool"/"run_tool", ...)``.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.adapters.typescript.refresh import _redact_tail
from repo_audit.adapters.expo import ExpoResult
from repo_audit.schema.finding import Evidence, Finding

# Default wall-clock bound for one expo-doctor run (RESEARCH: it reads local
# manifests + queries the RN Directory; 120s is generous). run_tool does the
# SIGTERM→5s→SIGKILL escalation on expiry (T-11-04-05).
_EXPO_TIMEOUT_SECONDS: float = 120.0

_SOURCE_TOOL = "expo-doctor"
_DIMENSION = "quality"
_TOOL_LABEL = "expo-doctor"

# Stable failure-block marker in expo-doctor's TEXT output. Lines beginning
# "Issue:" head each detected problem (RESEARCH Pitfall 3 recorded fixture).
_ISSUE_MARKER = "Issue:"


def _expo_argv(repo_path: Path) -> list[str]:
    """Build the expo-doctor argv (list[str] — shell=False guard, T-11-04-04).

    Prefer a target-local ``expo-doctor`` binary (resolve_tool: vendor →
    node_modules → PATH). When absent, fall back to the documented
    ``["npx", "expo-doctor"]`` invocation. Preferring the resolved binary over an
    ``npx`` auto-download is the T-11-04-03 network-egress mitigation; the literal
    ``npx`` fallback is the documented entry point when no local binary exists.
    """
    binary = resolve_tool(_SOURCE_TOOL, repo_path)
    if binary is not None:
        return [str(binary)]
    return ["npx", "expo-doctor"]


def collect_expo_doctor(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float = _EXPO_TIMEOUT_SECONDS,
) -> list[Finding]:
    """Run expo-doctor over ``repo_path`` and return quality Findings.

    Returns a ``list[Finding]`` (never an envelope — the Wave-0 contract test
    indexes the list). NEVER raises and NEVER hangs:

        * exit 0 → exactly one info-level ``quality`` Finding (all checks passed).
        * non-zero → one ``quality`` Finding per ``Issue:`` block, or one
          aggregate fallback Finding when no block matches (drift).
        * absent tool (EXEC_FAILED) → one ``unavailable`` Finding.
        * timeout (TIMED_OUT) → one ``unavailable`` (timeout-reason) Finding.
        * any unexpected exception → one ``unavailable`` Finding.
    """
    try:
        argv = _expo_argv(repo_path)
        inv = run_tool(
            argv,
            env=env,
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        if inv.returncode == TIMED_OUT:
            return [
                _unavailable_finding(
                    reason="expo_doctor_timeout",
                    detail=f"expo-doctor exceeded {timeout_seconds:.0f}s",
                )
            ]
        if inv.returncode == EXEC_FAILED:
            return [
                _unavailable_finding(
                    reason="expo_doctor_unavailable",
                    detail=f"expo-doctor could not be executed: {inv.stderr}".strip(),
                )
            ]

        if inv.returncode == 0:
            return [_pass_finding(inv.stdout)]

        # Non-zero exit: best-effort per-check parse, aggregate fallback on drift.
        findings = _parse_issue_blocks(inv.stdout)
        if findings:
            return findings
        return [_aggregate_fallback_finding(inv.stdout)]
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return [
            _unavailable_finding(
                reason="expo_doctor_unavailable",
                detail=f"{type(exc).__name__}: {exc}",
            )
        ]


def run_expo_doctor(
    repo_path: Path,
    *,
    timeout_seconds: float = _EXPO_TIMEOUT_SECONDS,
) -> ExpoResult:
    """Convenience wrapper: run :func:`collect_expo_doctor` with a default env.

    Builds a per-call cache-redirected scan env (mirrors ``run_semgrep`` /
    ``run_detekt``) and wraps the resulting findings in an :class:`ExpoResult`
    envelope — the shape Plan 05's scan-runner step consumes. The ``status`` is
    derived from whether the sole finding is an ``unavailable``/timeout Finding.
    """
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        findings = collect_expo_doctor(
            repo_path, env, timeout_seconds=timeout_seconds
        )

    status: str = "ok"
    notes = f"expo-doctor: {len(findings)} finding(s)"
    if len(findings) == 1 and findings[0].evidence_type == "unavailable":
        reason = findings[0].evidence.parsed_value.get("reason", "")
        status = "timeout" if reason == "expo_doctor_timeout" else "unavailable"
        notes = findings[0].evidence.output_snippet or status

    return ExpoResult(findings=findings, status=status, notes=notes)  # type: ignore[arg-type]


def _pass_finding(stdout: str) -> Finding:
    """Exit-0 → ONE info-level quality Finding: all expo-doctor checks passed."""
    # Keep a short, low-entropy summary line for the snippet (the full transcript
    # is bounded by the D-02 cap anyway, but a tight summary reads better).
    summary = ""
    for line in stdout.splitlines():
        if "passed" in line and "/" in line:
            summary = line.strip()
            break
    return Finding(
        dimension=_DIMENSION,
        severity="info",
        evidence_type="static",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="expo_doctor",
        rule_id="expo_doctor_pass",
        recommendation="All expo-doctor checks passed; no Expo config/health issues detected.",
        evidence=Evidence(
            tool=_TOOL_LABEL,
            output_snippet=summary or "all expo-doctor checks passed",
            parsed_value={"result": "pass"},
        ),
    )


def _parse_issue_blocks(stdout: str) -> list[Finding]:
    """Best-effort per-check parse: one quality Finding per ``Issue:`` block.

    Splits the stdout on ``Issue:`` markers; each block becomes one Finding whose
    ``output_snippet`` is the bounded/redacted block text. Returns an empty list
    when no marker matches (the caller then uses the aggregate fallback).
    """
    text = stdout or ""
    if _ISSUE_MARKER not in text:
        return []

    # Carve out each block from one "Issue:" marker to the next.
    blocks: list[str] = []
    idx = text.find(_ISSUE_MARKER)
    while idx != -1:
        nxt = text.find(_ISSUE_MARKER, idx + len(_ISSUE_MARKER))
        block = text[idx:nxt] if nxt != -1 else text[idx:]
        blocks.append(block.strip())
        idx = nxt

    findings: list[Finding] = []
    for i, block in enumerate(blocks):
        snippet = _redact_tail(block)  # bounded + secret-lint redacted (T-11-04-02)
        # The first line after "Issue:" is the human-readable check summary.
        first_line = block.splitlines()[0] if block else block
        findings.append(
            Finding(
                dimension=_DIMENSION,
                severity="minor",
                evidence_type="static",
                confidence="candidate",
                source_tool=_SOURCE_TOOL,
                source_collector="expo_doctor",
                rule_id="expo_doctor_issue",
                recommendation=(
                    "expo-doctor flagged a project health/config issue: "
                    f"{first_line[:200]}"
                ),
                evidence=Evidence(
                    tool=_TOOL_LABEL,
                    output_snippet=snippet,
                    parsed_value={"result": "issue", "block_index": i},
                ),
            )
        )
    return findings


def _aggregate_fallback_finding(stdout: str) -> Finding:
    """Drift fallback (RESEARCH A1): ONE quality Finding with the redacted tail.

    Used when the non-zero output does NOT match the ``Issue:`` line shape. The
    stdout tail is bounded AND run through the secret-lint primitive
    (``refresh._redact_tail``) before it reaches the Finding (T-11-04-02). We do
    NOT promise per-check granularity in this case.
    """
    return Finding(
        dimension=_DIMENSION,
        severity="minor",
        evidence_type="static",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="expo_doctor",
        rule_id="expo_doctor_issues",
        recommendation=(
            "expo-doctor reported issues (non-zero exit); see the output summary. "
            "Run `npx expo-doctor` for the full per-check detail."
        ),
        evidence=Evidence(
            tool=_TOOL_LABEL,
            output_snippet=_redact_tail(stdout or "expo-doctor reported issues"),
            parsed_value={"result": "issues", "parse": "aggregate_fallback"},
        ),
    )


def _unavailable_finding(*, reason: str, detail: str) -> Finding:
    """Absent / timeout / errored expo-doctor ⇒ one unavailable quality Finding."""
    return Finding(
        dimension=_DIMENSION,
        severity="minor",
        evidence_type="unavailable",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="expo_doctor",
        rule_id="expo_doctor_unavailable",
        recommendation=(
            "expo-doctor was not run (tool absent or timed out). Install it "
            "(`npx expo-doctor`) to surface Expo config/health issues."
        ),
        evidence=Evidence(
            tool=_TOOL_LABEL,
            output_snippet=detail,
            parsed_value={"reason": reason, "detail": detail},
        ),
    )


__all__ = [
    "collect_expo_doctor",
    "run_expo_doctor",
    "resolve_tool",
    "run_tool",
    "ExpoResult",
]
