"""CICD-02 — IaC (Terraform/k8s/CloudFormation/...) security collector (Phase 13, Plan 03).

``collect_checkov`` is the never-raising IaC-scan collection function, mirroring
``adapters/sast/semgrep.py::collect_semgrep`` (the verbatim SARIF-tool seam) and
the ``adapters/supply_chain/sbom.py`` write-artifact-to-tempdir-then-read pattern.
checkov emits SARIF, so findings route STRAIGHT through the shared
:func:`sarif_to_findings` (FND-01) into the ``security`` dimension.

Three things make checkov distinct from the other CI/CD collectors:

  * **SARIF goes to a FILE, not stdout (Pitfall 4).** checkov pollutes stdout with
    banners/progress; when ``-o sarif`` is combined with ``--output-file-path``,
    the SARIF lands at ``<out_dir>/results_sarif.sarif`` (Assumption A2). The
    collector reads + parses that FILE, never stdout.
  * **The file lands OUTSIDE the read-only target repo (REP-03 / T-13-WRITE).**
    When the caller does not supply an ``out_dir``, the collector creates one under
    a ``scan_tempdir()`` — never inside ``repo_path``. A PRIMARY containment guard
    refuses any out_dir under the repo before checkov is invoked (defense-in-depth
    ahead of the Plan-04 post-flight ``diff_git_status`` backstop).
  * **``--framework`` scoping EXCLUDES dockerfile/github_actions/secrets (Pitfall 3
    / T-13-DBLCOVER).** hadolint already covers Dockerfiles and zizmor already
    covers Actions, so checkov is scoped to the IaC subset
    (terraform/kubernetes/cloudformation/helm/kustomize/arm/bicep/serverless). A
    leaked ``CKV_DOCKER_``/``CKV_GHA_`` rule_id is the double-cover warning sign.

The five-gate ``collect_semgrep`` shape holds, in order:

    1. detect.find_iac_config FIRST — empty → status='unavailable' with a "no IaC
       config present" reason, WITHOUT invoking checkov (the D-13-05 first-class
       not-applicable degrade; checkov is the slowest tool — never run it on a
       repo with no Terraform/k8s/CFN).
    2. resolve_tool("checkov", repo, trusted_only=True) — CR-01. checkov is a
       Python package (PATH-only, NOT a vendorable static binary), so a PATH miss
       → status='unavailable' is the expected resolution path.
    3. run_tool([binary, "-d", ".", "-o", "sarif", "--output-file-path", <out_dir>,
       "--framework", <each framework>, "--soft-fail", "--quiet", "--compact"],
       cwd=repo) — the single shared subprocess seam (FND-04).
    4. Map the run_tool sentinels: TIMED_OUT (-2) → status='timeout'; EXEC_FAILED
       (-1) → status='unavailable'.
    5. Read + parse ``<out_dir>/results_sarif.sarif`` (NOT stdout — Pitfall 4);
       a missing file → status='unavailable' "no SARIF file". checkov ``--soft-fail``
       forces exit 0, so the gate is parse-of-FILE, never returncode (Pitfall 6).

``collect_checkov`` NEVER raises across its boundary and NEVER hangs: every
failure mode folds into a result status. ``run_tool``'s SIGTERM→5s→SIGKILL
escalation backs the no-hang guarantee with a generous ~300s bound (Pitfall 5;
``run_cicd`` runs OUTSIDE the 95s collector deadline).

NOTE: ``resolve_tool`` and ``run_tool`` are re-exported / module-level names so the
absent-binary and timeout tests can ``monkeypatch.setattr(iac, ...)``.

``default_dimension``, ``frameworks`` and ``timeout`` are resolved from
``adapter.yaml`` at CALL time (the Phase 3 no-module-load-caching lesson) — the
framework scoping (Pitfall 3) is config-driven, not hard-coded.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ruamel.yaml import YAML

from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.cicd import detect
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

CicdCollectorStatus = Literal["ok", "unavailable", "timeout"]

# Fallbacks used only if adapter.yaml is unreadable / the checkov block is absent —
# the descriptor is the source of truth at call time.
_CHECKOV_DEFAULT_DIMENSION = "security"
_CHECKOV_DEFAULT_TIMEOUT = 300.0
# The framework subset EXCLUDES dockerfile/github_actions/secrets (Pitfall 3) so
# checkov never double-covers hadolint/zizmor.
_CHECKOV_DEFAULT_FRAMEWORKS: tuple[str, ...] = (
    "terraform",
    "kubernetes",
    "cloudformation",
    "helm",
    "kustomize",
    "arm",
    "bicep",
    "serverless",
)

# checkov writes its SARIF here inside --output-file-path (Assumption A2).
_SARIF_FILENAME = "results_sarif.sarif"


@dataclass
class CheckovResult:
    """Never-raise envelope for :func:`collect_checkov`.

    Mirrors the Plan-02 ``ZizmorResult`` envelope: every failure mode (no IaC
    config, absent binary, exec-failure, timeout, missing/unparseable SARIF file)
    folds into ``status`` + ``notes`` rather than raised. ``status='ok'`` carries
    the security-dimension static/candidate findings read from the SARIF file.
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


def _resolve_frameworks(cfg: dict) -> tuple[str, ...]:
    """Resolve the framework subset from the checkov ``adapter.yaml`` block.

    Falls back to the documented default subset when the descriptor is missing /
    malformed. The subset EXCLUDES dockerfile/github_actions/secrets (Pitfall 3 /
    T-13-DBLCOVER) — config-driven scoping, not a hard-coded literal at the call
    site.
    """
    fw = cfg.get("frameworks")
    if isinstance(fw, (list, tuple)) and all(isinstance(x, str) for x in fw) and fw:
        return tuple(fw)
    return _CHECKOV_DEFAULT_FRAMEWORKS


def _checkov_argv(binary: Path, out_dir: Path, frameworks: tuple[str, ...]) -> list[str]:
    """Build the EXACT checkov argv (list[str], shell=False guard).

    ``-d .`` scans the repo (cwd=repo). ``-o sarif`` + ``--output-file-path
    <out_dir>`` route SARIF to ``<out_dir>/results_sarif.sarif`` (Pitfall 4 /
    Assumption A2) — NOT stdout, which is polluted by banners. ``--soft-fail``
    forces exit 0 even with findings (gate-on-parse, Pitfall 6). ``--quiet
    --compact`` reduce noise. ``--download-external-modules false`` pins checkov
    offline — no fetching of remote Terraform modules during a scan (T-13-EGRESS;
    the checkov analogue of zizmor's ``--offline``, satisfying the CLAUDE.md
    no-egress constraint). Each framework is a DISCRETE argv element (Pitfall 3
    scoping; T-13-INJECT — never interpolated into a shell string).
    """
    argv = [
        str(binary),
        "-d",
        ".",
        "-o",
        "sarif",
        "--output-file-path",
        str(out_dir),
        "--framework",
        *frameworks,
        "--download-external-modules",
        "false",
        "--soft-fail",
        "--quiet",
        "--compact",
    ]
    return argv


def _is_under(child: Path, parent: Path) -> bool:
    """True iff ``child`` resolves to ``parent`` or one of its descendants.

    Boundary-safe containment check (NOT a string-prefix test, which would treat a
    sibling ``/repo-2`` as inside ``/repo``). Used as the PRIMARY read-only guard:
    the SARIF out_dir must NOT be under the scanned repo (REP-03 / T-13-WRITE).
    """
    child_r = child.resolve()
    parent_r = parent.resolve()
    return child_r == parent_r or parent_r in child_r.parents


def collect_checkov(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float | None = None,
    out_dir: Path | None = None,
) -> CheckovResult:
    """Run checkov framework-scoped over the repo's IaC and return security findings.

    Args:
        repo_path: the target repository root.
        env: the child environment (cache-redirected by the caller).
        timeout_seconds: hard wall-clock bound; defaults to the ``adapter.yaml``
            ``timeout_ms`` for checkov (300s — Pitfall 5).
        out_dir: where checkov writes ``results_sarif.sarif``. When ``None``, a
            tempdir under ``scan_tempdir()`` is used — GUARANTEED outside
            ``repo_path`` (REP-03). A supplied out_dir is refused if it is under
            the repo.

    Returns:
        A :class:`CheckovResult`. ``status='ok'`` with security-dimension
        static/candidate findings read from the SARIF FILE on success;
        ``status='unavailable'`` when there is no IaC config, checkov is absent /
        exec-failed, the out_dir is under the repo, or no SARIF file is produced;
        ``status='timeout'`` on expiry. NEVER raises, NEVER hangs.
    """
    repo_path = Path(repo_path)
    cfg = _tool_config("checkov")
    default_dimension = cfg.get("default_dimension", _CHECKOV_DEFAULT_DIMENSION)
    frameworks = _resolve_frameworks(cfg)
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _CHECKOV_DEFAULT_TIMEOUT
        )

    # GATE 1 — no IaC config is a first-class not-applicable degrade (D-13-05).
    # checkov is the slowest tool — NEVER invoke it on a repo with no Terraform/k8s/CFN.
    if not detect.find_iac_config(repo_path):
        return CheckovResult(
            status="unavailable",
            notes="no IaC config present — checkov not applicable",
        )

    # GATE 2 — CR-01 trusted-only resolution. checkov is a Python package
    # (PATH-only, NOT vendorable as a static binary) — a miss is the expected
    # resolution path on a host without checkov.
    binary = resolve_tool("checkov", repo_path, trusted_only=True)
    if binary is None:
        return CheckovResult(
            status="unavailable",
            notes="checkov not found (vendor + PATH miss)",
        )

    with ExitStack() as stack:
        # Determine the SARIF output directory. When the caller did not supply one,
        # create a tempdir OUTSIDE the target repo (REP-03) whose lifecycle is tied
        # to this call. checkov MUST NOT write inside repo_path.
        if out_dir is None:
            out_dir = stack.enter_context(scan_tempdir())
        else:
            out_dir = Path(out_dir)

        # PRIMARY read-only guard (defense-in-depth ahead of the Plan-04 post-flight
        # diff_git_status backstop — REP-03 / T-13-WRITE): the SARIF dir must NOT be
        # under the scanned repo. Refuse rather than risk a target-repo write.
        if _is_under(out_dir, repo_path):
            return CheckovResult(
                status="unavailable",
                notes=(
                    "refusing to write checkov SARIF under the scanned repo "
                    "(read-only contract); out_dir must live outside the target tree"
                ),
            )
        out_dir.mkdir(parents=True, exist_ok=True)

        invocation = run_tool(
            _checkov_argv(binary, out_dir, frameworks),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 3/4 — run_tool structural sentinels (these NEVER raise).
        if invocation.returncode == TIMED_OUT:
            return CheckovResult(
                status="timeout",
                notes=f"checkov exceeded {timeout_seconds:.0f}s",
            )
        if invocation.returncode == EXEC_FAILED:
            return CheckovResult(
                status="unavailable",
                notes=f"checkov could not be executed: {invocation.stderr}",
            )

        # GATE 5 — read + parse the SARIF FILE, NOT stdout (Pitfall 4): stdout is
        # polluted by banners. A missing file (no catalogable IaC / checkov errored)
        # → unavailable. checkov --soft-fail forces exit 0, so the gate is
        # parse-of-FILE, never returncode (Pitfall 6).
        sarif_file = out_dir / _SARIF_FILENAME
        if not sarif_file.is_file():
            return CheckovResult(
                status="unavailable",
                notes="checkov produced no SARIF file (no IaC findings or checkov failed)",
            )

        try:
            sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
            findings = sarif_to_findings(
                sarif,
                source_tool="checkov",
                default_dimension=default_dimension,
                severity_map={},
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return CheckovResult(
                status="unavailable",
                notes=f"checkov SARIF parse failed: {type(exc).__name__}: {exc}",
            )

        return CheckovResult(
            findings=findings,
            status="ok",
            notes=f"checkov: {len(findings)} finding(s)",
        )


__all__ = [
    "CheckovResult",
    "collect_checkov",
    "resolve_tool",
    "run_tool",
]
