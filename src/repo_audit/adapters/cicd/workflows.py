"""CICD-01 — GitHub Actions workflow collectors (Phase 13, Plan 02).

Two never-raising collectors over ``.github/workflows``, both mirroring
``adapters/sast/semgrep.py::collect_semgrep`` (the verbatim SARIF-tool seam):

  * :func:`collect_zizmor` — workflow SECURITY (injection, unpinned/forgeable
    actions, secret-exposure). zizmor emits SARIF, so it routes STRAIGHT through
    the shared :func:`sarif_to_findings` (FND-01) into the ``security`` dimension.
    Runs ``--offline`` (Pitfall 7 / T-13-EGRESS): no network egress, deterministic.
  * :func:`collect_actionlint` — workflow CORRECTNESS lint. actionlint's SARIF is
    an impractical Go-template (Pitfall 1), so D-13-03 routes it through the thin
    :func:`_actionlint_json_to_findings` JSON map (a dedicated transform, NOT a
    fork of ``sarif_to_findings``) into the ``process`` dimension at
    ``severity="minor"``.

Both collectors follow the five-gate ``collect_semgrep`` shape, in order:

    1. detect.find_workflows FIRST — empty → status='unavailable' with a
       "no .github/workflows" reason, WITHOUT invoking the tool (the D-13-05
       first-class not-applicable degrade; distinct from "tool absent").
    2. resolve_tool(..., trusted_only=True) — CR-01 (skips target-repo
       node_modules/.bin); None → status='unavailable'.
    3. run_tool([...], env=..., cwd=repo, timeout_seconds=...) — the single
       shared subprocess seam (FND-04): shell=False, list[str] argv, explicit
       timeout, SIGTERM→5s→SIGKILL.
    4. Map the run_tool sentinels: TIMED_OUT (-2) → status='timeout';
       EXEC_FAILED (-1) → status='unavailable'.
    5. Gate on whether stdout PARSES (NOT on returncode — Pitfall 6): zizmor
       ``--format=sarif`` exits 0 always, but actionlint exits 1 on findings, so
       a non-zero exit with parseable output is NOT a failure. Unparseable
       stdout → status='unavailable'.

Neither collector ever raises across its boundary and neither hangs: every
failure mode (no workflows, absent binary, exec-failure, timeout, unparseable
output, a parse exception) folds into a result status. ``run_tool``'s
SIGTERM→5s→SIGKILL escalation backs the no-hang guarantee.

NOTE: ``resolve_tool`` is re-exported in ``__all__`` so the absent-binary tests
can ``monkeypatch.setattr(workflows, "resolve_tool", ...)``.

``default_dimension`` and ``timeout`` are resolved from ``adapter.yaml`` at CALL
time (the Phase 3 no-module-load-caching lesson) — never hard-coded in a way
that bypasses the descriptor.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ruamel.yaml import YAML

from repo_audit.adapters.cicd import detect
from repo_audit.adapters.cicd.actionlint_json import _actionlint_json_to_findings
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

CicdCollectorStatus = Literal["ok", "unavailable", "timeout"]

# Fallbacks used only if adapter.yaml is unreadable / a tool block is absent —
# the descriptor is the source of truth at call time.
_ZIZMOR_DEFAULT_DIMENSION = "security"
_ZIZMOR_DEFAULT_TIMEOUT = 120.0
_ACTIONLINT_DEFAULT_DIMENSION = "process"
_ACTIONLINT_DEFAULT_TIMEOUT = 60.0


@dataclass
class ZizmorResult:
    """Never-raise envelope for :func:`collect_zizmor`.

    Mirrors ``SastResult``: every failure mode (no workflows, absent binary,
    exec-failure, timeout, unparseable SARIF) folds into ``status`` + ``notes``
    rather than raised. ``status='ok'`` carries the security-dimension
    static/candidate findings.
    """

    findings: list[Finding] = field(default_factory=list)
    status: CicdCollectorStatus = "ok"
    notes: str = ""


@dataclass
class ActionlintResult:
    """Never-raise envelope for :func:`collect_actionlint`.

    Same shape as :class:`ZizmorResult`. ``status='ok'`` carries the
    process-dimension minor/candidate findings mapped from actionlint JSON.
    """

    findings: list[Finding] = field(default_factory=list)
    status: CicdCollectorStatus = "ok"
    notes: str = ""


def _load_cicd_config() -> dict:
    """Load the cicd ``adapter.yaml`` descriptor via the safe YAML loader (T-03-01).

    Resolved at CALL time (no module-load caching — the Phase 3 lesson). Returns
    an empty dict on any read/parse failure so the collectors fall back to their
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


def _zizmor_argv(binary: Path, workflows_dir: Path) -> list[str]:
    """Build the EXACT zizmor argv (list[str], shell=False guard).

    ``--format=sarif`` selects the single SARIF output path (FND-01). ``--offline``
    forbids network egress (Pitfall 7 / T-13-EGRESS) so the scan is deterministic
    and leaks no action metadata. ``workflows_dir`` is a SINGLE argv element —
    never interpolated into a shell string (T-13-INJECT).
    """
    return [str(binary), "--format=sarif", "--offline", str(workflows_dir)]


def _zizmor_env(env: dict[str, str]) -> dict[str, str]:
    """Layer ``ZIZMOR_OFFLINE=1`` onto the caller's scan env (Pitfall 7).

    Belt-and-braces with the ``--offline`` flag: no network during a scan.
    """
    e = dict(env)
    e["ZIZMOR_OFFLINE"] = "1"
    return e


def collect_zizmor(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float | None = None,
) -> ZizmorResult:
    """Run zizmor over ``.github/workflows`` and return security findings.

    Args:
        repo_path: the target repository root.
        env: the child environment (cache-redirected by the caller). The
            ``ZIZMOR_OFFLINE=1`` var is layered on top via :func:`_zizmor_env`.
        timeout_seconds: hard wall-clock bound; defaults to the ``adapter.yaml``
            ``timeout_ms`` for zizmor (120s).

    Returns:
        A :class:`ZizmorResult`. ``status='ok'`` with security-dimension
        static/candidate findings on success; ``status='unavailable'`` when there
        are no workflows, zizmor is absent / exec-failed, or stdout is not
        parseable SARIF; ``status='timeout'`` on expiry. NEVER raises, NEVER hangs.
    """
    repo_path = Path(repo_path)
    cfg = _tool_config("zizmor")
    default_dimension = cfg.get("default_dimension", _ZIZMOR_DEFAULT_DIMENSION)
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _ZIZMOR_DEFAULT_TIMEOUT
        )

    # GATE 1 — no workflows is a first-class not-applicable degrade (D-13-05).
    # Distinct from "tool absent": the tool is NOT invoked.
    if not detect.find_workflows(repo_path):
        return ZizmorResult(
            status="unavailable",
            notes="no .github/workflows present — zizmor not applicable",
        )

    # GATE 2 — CR-01 trusted-only resolution (skips target-repo node_modules/.bin).
    binary = resolve_tool("zizmor", repo_path, trusted_only=True)
    if binary is None:
        return ZizmorResult(
            status="unavailable",
            notes="zizmor not found (vendor + PATH miss)",
        )

    workflows_dir = repo_path / ".github" / "workflows"
    invocation = run_tool(
        _zizmor_argv(binary, workflows_dir),
        env=_zizmor_env(env),
        cwd=repo_path,
        timeout_seconds=timeout_seconds,
    )

    # GATE 3/4 — run_tool structural sentinels (these NEVER raise).
    if invocation.returncode == TIMED_OUT:
        return ZizmorResult(
            status="timeout",
            notes=f"zizmor exceeded {timeout_seconds:.0f}s",
        )
    if invocation.returncode == EXEC_FAILED:
        return ZizmorResult(
            status="unavailable",
            notes=f"zizmor could not be executed: {invocation.stderr}",
        )

    # GATE 5 — gate on whether stdout PARSES as SARIF, NOT on returncode: zizmor
    # `--format=sarif` exits 0 always, so a non-zero exit is a tool problem rather
    # than a "found issues" signal (Pitfall 6).
    try:
        sarif = json.loads(invocation.stdout)
    except (json.JSONDecodeError, ValueError):
        return ZizmorResult(
            status="unavailable",
            notes="zizmor produced no parseable SARIF",
        )

    # SARIF is the SINGLE finding source (FND-01). severity_map={} selects the
    # parser's faithful default level map; the parser stamps evidence_type='static'
    # + confidence='candidate' and enforces the SCH-04 candidate cap.
    try:
        findings = sarif_to_findings(
            sarif,
            source_tool="zizmor",
            default_dimension=default_dimension,
            severity_map={},
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return ZizmorResult(
            status="unavailable",
            notes=f"zizmor SARIF parse failed: {type(exc).__name__}: {exc}",
        )

    return ZizmorResult(
        findings=findings,
        status="ok",
        notes=f"zizmor: {len(findings)} finding(s)",
    )


def _actionlint_argv(binary: Path) -> list[str]:
    """Build the EXACT actionlint argv (list[str], shell=False guard).

    ``-format '{{json .}}'`` selects the JSON output path (D-13-03 / Pitfall 1 —
    actionlint's SARIF reporter is an impractical Go-template). ``-no-color``
    keeps the JSON clean. Run with ``cwd=repo_path`` so actionlint discovers
    ``.github/workflows`` itself; the JSON ``filepath`` keys are repo-relative.
    """
    return [str(binary), "-format", "{{json .}}", "-no-color"]


def collect_actionlint(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float | None = None,
) -> ActionlintResult:
    """Run actionlint over ``.github/workflows`` and return process findings.

    Args:
        repo_path: the target repository root (actionlint discovers workflows
            relative to ``cwd=repo_path``).
        env: the child environment (cache-redirected by the caller).
        timeout_seconds: hard wall-clock bound; defaults to the ``adapter.yaml``
            ``timeout_ms`` for actionlint (60s).

    Returns:
        An :class:`ActionlintResult`. ``status='ok'`` with process-dimension
        minor/candidate findings on success; ``status='unavailable'`` when there
        are no workflows, actionlint is absent / exec-failed, or stdout is not a
        parseable JSON array; ``status='timeout'`` on expiry. NEVER raises.
    """
    repo_path = Path(repo_path)
    cfg = _tool_config("actionlint")
    default_dimension = cfg.get("default_dimension", _ACTIONLINT_DEFAULT_DIMENSION)
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _ACTIONLINT_DEFAULT_TIMEOUT
        )

    # GATE 1 — no workflows is a first-class not-applicable degrade (D-13-05).
    if not detect.find_workflows(repo_path):
        return ActionlintResult(
            status="unavailable",
            notes="no .github/workflows present — actionlint not applicable",
        )

    # GATE 2 — CR-01 trusted-only resolution.
    binary = resolve_tool("actionlint", repo_path, trusted_only=True)
    if binary is None:
        return ActionlintResult(
            status="unavailable",
            notes="actionlint not found (vendor + PATH miss)",
        )

    invocation = run_tool(
        _actionlint_argv(binary),
        env=dict(env),
        cwd=repo_path,
        timeout_seconds=timeout_seconds,
    )

    # GATE 3/4 — run_tool structural sentinels.
    if invocation.returncode == TIMED_OUT:
        return ActionlintResult(
            status="timeout",
            notes=f"actionlint exceeded {timeout_seconds:.0f}s",
        )
    if invocation.returncode == EXEC_FAILED:
        return ActionlintResult(
            status="unavailable",
            notes=f"actionlint could not be executed: {invocation.stderr}",
        )

    # GATE 5 — gate on whether stdout PARSES as a JSON array, NOT on returncode:
    # actionlint exits 1 when it FINDS problems (parseable JSON — that's 'ok') and
    # exit 2 on a malformed -format template (non-JSON — that's 'unavailable').
    # Pitfall 1.
    try:
        errors = json.loads(invocation.stdout)
    except (json.JSONDecodeError, ValueError):
        return ActionlintResult(
            status="unavailable",
            notes="actionlint produced no parseable JSON",
        )
    if not isinstance(errors, list):
        return ActionlintResult(
            status="unavailable",
            notes="actionlint JSON was not the expected array",
        )

    try:
        findings = _actionlint_json_to_findings(
            errors, default_dimension=default_dimension
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return ActionlintResult(
            status="unavailable",
            notes=f"actionlint JSON map failed: {type(exc).__name__}: {exc}",
        )

    return ActionlintResult(
        findings=findings,
        status="ok",
        notes=f"actionlint: {len(findings)} finding(s)",
    )


__all__ = [
    "ActionlintResult",
    "ZizmorResult",
    "collect_actionlint",
    "collect_zizmor",
    "resolve_tool",
]
