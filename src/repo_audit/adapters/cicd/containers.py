"""CICD-02 — Dockerfile security collector (Phase 13, Plan 03).

``collect_hadolint`` is the never-raising Dockerfile-lint collection function,
mirroring ``adapters/sast/semgrep.py::collect_semgrep`` (the verbatim SARIF-tool
seam) and the Plan-02 ``cicd/workflows.py`` envelopes. hadolint emits SARIF, so
findings route STRAIGHT through the shared :func:`sarif_to_findings` (FND-01)
into the ``security`` dimension.

The defining shape of this collector — distinct from the workflow collectors — is
that hadolint is run **once per discovered Dockerfile**, with the REAL file path
passed as a discrete argv element (NEVER stdin — Pitfall 2). hadolint reads from
stdin when invoked as ``hadolint -`` and then stamps ``artifactLocation.uri = "-"``
into the SARIF; passing the real path instead makes hadolint stamp the real
filename. Because the recorded fixture (and some hadolint versions on stdin) can
still carry ``"-"`` or a repo-relative uri, each parsed finding's ``file`` is
normalized to the absolute Dockerfile path the collector actually scanned — so a
finding always points at a real file, never the stdin sentinel.

Per-file, the five-gate ``collect_semgrep`` shape holds in order:

    1. detect.find_dockerfiles FIRST — empty → status='unavailable' with a
       "no Dockerfile present" reason, WITHOUT invoking hadolint (the D-13-05
       first-class not-applicable degrade; distinct from "tool absent").
    2. resolve_tool("hadolint", repo, trusted_only=True) — CR-01 (skips
       target-repo node_modules/.bin); None → status='unavailable'.
    3. For each Dockerfile: run_tool([binary, "--format", "sarif", "--no-fail",
       <real path>], env=..., cwd=repo, timeout_seconds=...) — the single shared
       subprocess seam (FND-04): shell=False, list[str] argv, explicit timeout,
       SIGTERM→5s→SIGKILL.
    4. Map the run_tool sentinels: TIMED_OUT (-2) short-circuits the WHOLE
       collector to status='timeout'; EXEC_FAILED (-1) → status='unavailable'.
    5. Gate on whether stdout PARSES as SARIF (NOT on returncode — Pitfall 6):
       hadolint ``--no-fail`` forces exit 0, but we defensively gate on parse so a
       non-zero exit with parseable output is still 'ok'. Findings from every file
       merge via the shared parser.

``collect_hadolint`` NEVER raises across its boundary and NEVER hangs: every
failure mode folds into a result status. ``run_tool``'s SIGTERM→5s→SIGKILL
escalation backs the no-hang guarantee.

NOTE: ``resolve_tool`` and ``run_tool`` are re-exported / module-level names so the
absent-binary and timeout tests can ``monkeypatch.setattr(containers, ...)``.

``default_dimension`` and ``timeout`` are resolved from ``adapter.yaml`` at CALL
time (the Phase 3 no-module-load-caching lesson).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ruamel.yaml import YAML

from repo_audit.adapters.cicd import detect
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

CicdCollectorStatus = Literal["ok", "unavailable", "timeout"]

# Fallbacks used only if adapter.yaml is unreadable / the hadolint block is
# absent — the descriptor is the source of truth at call time.
_HADOLINT_DEFAULT_DIMENSION = "security"
_HADOLINT_DEFAULT_TIMEOUT = 120.0

# The stdin sentinel hadolint stamps into artifactLocation.uri when reading from
# ``-``. We invoke per-file with a real path, but normalize defensively.
_STDIN_URI = "-"


@dataclass
class HadolintResult:
    """Never-raise envelope for :func:`collect_hadolint`.

    Mirrors the Plan-02 ``ZizmorResult`` envelope: every failure mode (no
    Dockerfile, absent binary, exec-failure, timeout, unparseable SARIF) folds
    into ``status`` + ``notes`` rather than raised. ``status='ok'`` carries the
    security-dimension static/candidate findings merged across all Dockerfiles.
    """

    findings: list[Finding] = field(default_factory=list)
    status: CicdCollectorStatus = "ok"
    notes: str = ""


def _load_cicd_config() -> dict:
    """Load the cicd ``adapter.yaml`` descriptor via the safe YAML loader (T-03-01).

    Resolved at CALL time (no module-load caching — the Phase 3 lesson). Returns
    an empty dict on any read/parse failure so the collector falls back to its
    documented defaults rather than raising.
    """
    try:
        yaml = YAML(typ="safe")
        with (Path(__file__).parent / "adapter.yaml").open(encoding="utf-8") as fh:
            return yaml.load(fh) or {}
    except Exception:  # noqa: BLE001 — descriptor read must never break a scan
        return {}


def _tool_config(tool: str) -> dict:
    """Return the per-tool block from ``adapter.yaml`` (empty dict if absent)."""
    cfg = _load_cicd_config()
    return (cfg.get("tools") or {}).get(tool) or {}


def _hadolint_argv(binary: Path, dockerfile: Path) -> list[str]:
    """Build the EXACT hadolint argv for a SINGLE Dockerfile (list[str] guard).

    ``--format sarif`` selects the single SARIF output path (FND-01). ``--no-fail``
    forces exit 0 even when lint findings exist, so the parse-gate (Pitfall 6) is
    the authoritative success signal. The Dockerfile path is passed as a DISCRETE
    argv element — NEVER stdin (Pitfall 2) and never interpolated into a shell
    string (T-13-INJECT) — so hadolint stamps the real filename into the SARIF
    instead of the ``"-"`` stdin sentinel.
    """
    return [str(binary), "--format", "sarif", "--no-fail", str(dockerfile)]


def _stamp_file(findings: list[Finding], dockerfile: Path) -> list[Finding]:
    """Normalize each finding's ``file`` to the real Dockerfile path (Pitfall 2).

    hadolint-on-stdin (and the recorded fixture) stamp ``artifactLocation.uri =
    "-"``; some versions emit a repo-relative bare name. Either way the collector
    KNOWS the absolute path it scanned, so it overrides ``file`` with that path —
    a finding always points at a real Dockerfile, never the stdin sentinel. Uses
    ``model_copy`` (immutable rewrite) to keep every other field intact.
    """
    real = str(dockerfile)
    stamped: list[Finding] = []
    for f in findings:
        if f.file in (None, "", _STDIN_URI) or not Path(f.file).is_absolute():
            stamped.append(f.model_copy(update={"file": real}))
        else:
            stamped.append(f)
    return stamped


def collect_hadolint(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float | None = None,
) -> HadolintResult:
    """Run hadolint over each discovered Dockerfile and return security findings.

    hadolint is invoked ONCE PER Dockerfile with the real path as argv (Pitfall
    2), and the findings from every file are merged via the shared parser.

    Args:
        repo_path: the target repository root.
        env: the child environment (cache-redirected by the caller).
        timeout_seconds: hard per-file wall-clock bound; defaults to the
            ``adapter.yaml`` ``timeout_ms`` for hadolint (120s).

    Returns:
        A :class:`HadolintResult`. ``status='ok'`` with security-dimension
        static/candidate findings merged across all Dockerfiles on success;
        ``status='unavailable'`` when there are no Dockerfiles, hadolint is
        absent / exec-failed, or stdout is not parseable SARIF; ``status='timeout'``
        when any file's run expires. NEVER raises, NEVER hangs.
    """
    repo_path = Path(repo_path)
    cfg = _tool_config("hadolint")
    default_dimension = cfg.get("default_dimension", _HADOLINT_DEFAULT_DIMENSION)
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _HADOLINT_DEFAULT_TIMEOUT
        )

    # GATE 1 — no Dockerfile is a first-class not-applicable degrade (D-13-05).
    # Distinct from "tool absent": hadolint is NOT invoked.
    dockerfiles = detect.find_dockerfiles(repo_path)
    if not dockerfiles:
        return HadolintResult(
            status="unavailable",
            notes="no Dockerfile present — hadolint not applicable",
        )

    # GATE 2 — CR-01 trusted-only resolution (skips target-repo node_modules/.bin).
    binary = resolve_tool("hadolint", repo_path, trusted_only=True)
    if binary is None:
        return HadolintResult(
            status="unavailable",
            notes="hadolint not found (vendor + PATH miss)",
        )

    all_findings: list[Finding] = []
    parsed_files = 0
    for dockerfile in dockerfiles:
        invocation = run_tool(
            _hadolint_argv(binary, dockerfile),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 3/4 — run_tool structural sentinels (these NEVER raise). A timeout on
        # ANY file short-circuits the whole collector to 'timeout' (honest no-hang).
        if invocation.returncode == TIMED_OUT:
            return HadolintResult(
                status="timeout",
                notes=f"hadolint exceeded {timeout_seconds:.0f}s on {dockerfile.name}",
            )
        if invocation.returncode == EXEC_FAILED:
            return HadolintResult(
                status="unavailable",
                notes=f"hadolint could not be executed: {invocation.stderr}",
            )

        # GATE 5 — gate on whether stdout PARSES as SARIF, NOT on returncode:
        # hadolint --no-fail exits 0 always, so a non-zero exit is a tool problem
        # rather than a "found issues" signal (Pitfall 6). Wrap parse + map per
        # file so one unparseable file does not crash the collector.
        try:
            sarif = json.loads(invocation.stdout)
            findings = sarif_to_findings(
                sarif,
                source_tool="hadolint",
                default_dimension=default_dimension,
                severity_map={},
            )
        except Exception:  # noqa: BLE001 — never raise across the boundary
            continue
        all_findings.extend(_stamp_file(findings, dockerfile))
        parsed_files += 1

    # If NOT a single Dockerfile produced parseable SARIF, the tool is effectively
    # unusable here — degrade honestly rather than report a silent empty success.
    if parsed_files == 0:
        return HadolintResult(
            status="unavailable",
            notes="hadolint produced no parseable SARIF for any Dockerfile",
        )

    return HadolintResult(
        findings=all_findings,
        status="ok",
        notes=f"hadolint: {len(all_findings)} finding(s) across {parsed_files} Dockerfile(s)",
    )


__all__ = [
    "HadolintResult",
    "collect_hadolint",
    "resolve_tool",
    "run_tool",
]
