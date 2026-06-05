"""BYO-02 — the 5 first-class opt-in commercial wrappers + registry.

"First-class" means **pre-wired + discoverable**, NOT heavy per-tool adapters.
Five commercial tools are pre-named here, each DEFAULT-OFF behind the
:class:`ByoToolConfig` attestation gate (BYO-01): a disabled/unattested tool
never runs and produces no findings.

The RESEARCH correction — normalizer surface is 3, not 6:

    * **Semgrep Pro**, **Snyk** (``test`` + ``code test``) and **GitGuardian
      ggshield** all emit SARIF natively → they route through the
      :func:`run_byo_tool` pre-read seam (Plan 16-06 Task 1) and reuse the
      shared ``sarif_to_findings`` path. NO per-tool parser.
    * **Socket.dev** and **SonarQube** emit tool-native JSON only → they run
      their binary via ``run_tool`` then their per-tool normalizer
      (``socket_json_to_findings`` / ``sonar_json_to_findings``).

Every emitted finding is TAGGED ``source_tool`` + its dimension and lands at the
candidate cap (the SARIF path and the two JSON normalizers all enforce SCH-04).
There is **NO cross-tool confidence-raise logic anywhere in this module**
(D-16-15) — confidence-raising is Phase 17's sole job. This module only TAGS.

Dimension mapping (16-RESEARCH §BYO-02 lane table):
    semgrep-pro → security, snyk → security, ggshield → security,
    socket → security, sonarqube → quality.

Like every cross-stack step (``run_sca`` / ``run_sast`` / ``run_mobile``) this
NEVER raises across its boundary (D-25): a tool that is absent / unentitled /
errors becomes unavailable and the OTHER tools still run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Optional

from repo_audit.adapters.byo.adapter import run_byo_tool
from repo_audit.adapters.byo.config import ByoToolConfig
from repo_audit.adapters.byo.normalizers.socket_json import (
    socket_json_to_findings,
)
from repo_audit.adapters.byo.normalizers.sonar_json import (
    sonar_json_to_findings,
)
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

CommercialStatus = Literal["ok", "partial", "unavailable", "timeout", "not_applicable"]

# Output kind a tool emits — decides which path it takes.
OutputKind = Literal["sarif", "json"]

# A normalizer maps a tool-native JSON doc into Findings (JSON tools only).
Normalizer = Callable[..., list[Finding]]

# A produce-argv builder: (binary, repo_path, sarif_output) -> argv[str].
# For SARIF tools the argv writes its SARIF to sarif_output (resolved under the
# repo by the run_byo_tool seam). For JSON tools sarif_output is unused.
ArgvBuilder = Callable[[Path, Path, str], list[str]]


@dataclass(frozen=True)
class _CommercialSpec:
    """A single first-class commercial tool's wiring (no logic, just data)."""

    name: str
    output_kind: OutputKind
    default_dimension: str
    argv_builder: ArgvBuilder
    normalizer: Optional[Normalizer] = None  # JSON tools only
    binary: str = ""  # the binary name to resolve (defaults to name)
    # CR-01: where a SARIF tool's output lands. "stdout" tools (Semgrep --sarif,
    # ggshield --format sarif) print SARIF to stdout and take no --output flag;
    # "file" tools (Snyk --sarif-file-output) write cfg.sarif_output. Ignored for
    # JSON tools (they always read stdout via their normalizer).
    sarif_source: Literal["file", "stdout"] = "file"

    def binary_name(self) -> str:
        return self.binary or self.name


@dataclass
class CommercialScanResult:
    """The never-raise envelope ``run_byo_commercial`` returns (mirrors
    ``TestDepthScanResult`` / ``MobileScanResult``).

    ``scan_runner`` reads ``findings`` into the merged finding set, ORs
    ``status != "ok"`` into the partial flag, and folds ``notes`` /
    ``ledger_notes`` into the scope ledger (SAFE-08 honest disclosure).
    """

    findings: list[Finding] = field(default_factory=list)
    status: CommercialStatus = "not_applicable"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


# --- the 5 produce-argv builders ------------------------------------------
# These are OUR constants (never target-supplied); the repo path is always a
# single argv element, never interpolated into a shell string (shell=False).


def _semgrep_pro_argv(binary: Path, repo_path: Path, sarif_output: str) -> list[str]:
    """Semgrep Pro — extends the CE argv with ``--pro`` (interfile taint).

    Reuses ``sast/semgrep.py::_semgrep_argv`` so the Pro argv is byte-identical
    to the audited CE argv plus ``--pro``; the SARIF is emitted to stdout and the
    seam captures it (Semgrep prints SARIF to stdout with ``--sarif``).
    """
    from repo_audit.adapters.sast.noise import DEFAULT_EXCLUDES
    from repo_audit.adapters.sast.semgrep import _semgrep_argv

    return _semgrep_argv(
        binary, repo_path, ["p/owasp-top-ten"], DEFAULT_EXCLUDES, pro=True
    )


def _snyk_argv(binary: Path, repo_path: Path, sarif_output: str) -> list[str]:
    """Snyk Code — SARIF via ``--sarif-file-output`` (JSON==SARIF for code)."""
    return [
        str(binary),
        "code",
        "test",
        f"--sarif-file-output={sarif_output}",
        str(repo_path),
    ]


def _ggshield_argv(binary: Path, repo_path: Path, sarif_output: str) -> list[str]:
    """GitGuardian ggshield — secret scan with native SARIF output."""
    return [
        str(binary),
        "secret",
        "scan",
        "repo",
        str(repo_path),
        "--format",
        "sarif",
    ]


def _socket_argv(binary: Path, repo_path: Path, sarif_output: str) -> list[str]:
    """Socket.dev — JSON only (``socket scan create --json``)."""
    return [str(binary), "scan", "create", "--json", str(repo_path)]


def _sonar_argv(binary: Path, repo_path: Path, sarif_output: str) -> list[str]:
    """SonarQube CLI — JSON issues export (api/issues/search shape)."""
    return [str(binary), "issues", "search", "--json"]


# The registry: each first-class commercial tool, default-OFF until its
# ByoToolConfig is enabled + attested.
COMMERCIAL_TOOLS: dict[str, _CommercialSpec] = {
    "semgrep-pro": _CommercialSpec(
        name="semgrep-pro",
        output_kind="sarif",
        default_dimension="security",
        argv_builder=_semgrep_pro_argv,
        binary="semgrep",
        sarif_source="stdout",  # CR-01: semgrep --sarif prints to stdout
    ),
    "snyk": _CommercialSpec(
        name="snyk",
        output_kind="sarif",
        default_dimension="security",
        argv_builder=_snyk_argv,
        # snyk writes a file via --sarif-file-output (default "file")
    ),
    "gitguardian": _CommercialSpec(
        name="gitguardian",
        output_kind="sarif",
        default_dimension="security",
        argv_builder=_ggshield_argv,
        binary="ggshield",
        sarif_source="stdout",  # CR-01: ggshield --format sarif prints to stdout
    ),
    "socket": _CommercialSpec(
        name="socket",
        output_kind="json",
        default_dimension="security",
        argv_builder=_socket_argv,
        normalizer=socket_json_to_findings,
    ),
    "sonarqube": _CommercialSpec(
        name="sonarqube",
        output_kind="json",
        default_dimension="quality",
        argv_builder=_sonar_argv,
        normalizer=sonar_json_to_findings,
        binary="sonar-scanner",
    ),
}

# Default wall-clock bound for a JSON tool's live invocation (the SARIF tools
# carry their own bound via ByoToolConfig.timeout_seconds at the seam).
_JSON_TIMEOUT_SECONDS: float = 600.0


def run_byo_commercial(
    repo_path: str | Path,
    *,
    base_env: dict[str, str],
    scratch_dir: str | Path,
    configs: dict[str, ByoToolConfig],
) -> CommercialScanResult:
    """Run the configured first-class commercial tools; aggregate their findings.

    Args:
        repo_path: the scan root.
        base_env: the base (cache-redirected) child environment. The per-tool
            credential is layered on at the seam by env-var NAME (never stored).
        scratch_dir: a writable dir OUTSIDE the target repo for any tool that
            needs a scratch artifact (read-only-on-target posture).
        configs: ``{tool_name: ByoToolConfig}`` — typically the commercial slice
            of ``load_byo_config``. Each entry is default-OFF; a tool absent from
            ``configs`` or whose ``should_run`` is False is skipped.

    Returns:
        A :class:`CommercialScanResult`. ``findings`` are tagged ``source_tool``
        + dimension at the candidate cap. ``status`` is ``ok`` (all ran),
        ``partial`` (some ran), ``unavailable`` (none ran), or
        ``not_applicable`` (none configured). NEVER raises (D-25). Holds NO
        cross-tool confidence-raise logic — Phase 17 owns confidence-raising.
    """
    repo = Path(repo_path)
    findings: list[Finding] = []
    ledger_notes: list[str] = []
    statuses: list[str] = []

    for name, spec in COMMERCIAL_TOOLS.items():
        cfg = configs.get(name)
        # Gate: default-OFF — a missing/disabled/unattested tool never runs.
        if cfg is None or not cfg.should_run:
            continue

        per_tool = _run_one(spec, cfg, repo, base_env, scratch_dir)
        statuses.append(per_tool.status)
        ledger_notes.append(per_tool.notes)
        findings.extend(per_tool.findings)

    if not statuses:
        return CommercialScanResult(
            status="not_applicable",
            notes="no commercial tools enabled + attested (all default-OFF).",
        )

    return CommercialScanResult(
        findings=findings,
        status=_derive_status(statuses),
        notes=f"commercial: {len(findings)} finding(s) across {len(statuses)} tool(s)",
        ledger_notes=ledger_notes,
    )


def _run_one(
    spec: _CommercialSpec,
    cfg: ByoToolConfig,
    repo: Path,
    base_env: dict[str, str],
    scratch_dir: str | Path,
) -> CommercialScanResult:
    """Run a single enabled+attested commercial tool. NEVER raises."""
    # CR-01: security scanners resolve trusted-only — a binary a hostile target
    # repo planted in node_modules/.bin is never executed.
    binary = resolve_tool(spec.binary_name(), repo, trusted_only=True)
    if binary is None:
        return CommercialScanResult(
            status="unavailable",
            notes=f"{spec.name}: binary not found (vendor + PATH miss) — skipped.",
        )

    produce_argv = spec.argv_builder(binary, repo, cfg.sarif_output)

    if spec.output_kind == "sarif":
        # Route the 3 SARIF tools through the shared run_byo_tool seam: the
        # produce-argv runs the binary, then the SAME sarif_to_findings parses
        # its output. No per-tool parser; the seam tags source_tool + applies
        # the candidate cap.
        adapter_result = run_byo_tool(
            cfg,
            repo,
            produce_argv=produce_argv,
            base_env=base_env,
            sarif_from_stdout=(spec.sarif_source == "stdout"),
        )
        status: CommercialStatus = (
            "ok" if adapter_result.status == "ok" else adapter_result.status  # type: ignore[assignment]
        )
        return CommercialScanResult(
            findings=list(adapter_result.findings),
            status=status,
            notes=f"{spec.name}: {adapter_result.status} "
            f"({len(adapter_result.findings)} finding(s)).",
        )

    # JSON tools: run the binary then the per-tool normalizer.
    return _run_json_tool(spec, cfg, binary, produce_argv, repo, base_env)


def _run_json_tool(
    spec: _CommercialSpec,
    cfg: ByoToolConfig,
    binary: Path,
    produce_argv: list[str],
    repo: Path,
    base_env: dict[str, str],
) -> CommercialScanResult:
    """Run a JSON-emitting commercial tool then normalize. NEVER raises."""
    import json as _json
    import os as _os

    # Credential by env-var NAME at runtime (Pitfall 8 — never stored/logged).
    env = dict(base_env)
    if cfg.credential_env:
        token = _os.environ.get(cfg.credential_env)
        if token is not None:
            env[cfg.credential_env] = token

    inv = run_tool(
        produce_argv,
        env=env,
        cwd=repo,
        timeout_seconds=float(cfg.timeout_seconds or _JSON_TIMEOUT_SECONDS),
    )

    # Gate on the honest sentinels; a non-zero exit is NOT a failure for these
    # tools (Pitfall 9) — the real gate is whether the JSON parses.
    if inv.returncode == TIMED_OUT:
        return CommercialScanResult(
            status="timeout", notes=f"{spec.name}: exceeded {cfg.timeout_seconds}s."
        )
    if inv.returncode == EXEC_FAILED:
        return CommercialScanResult(
            status="unavailable", notes=f"{spec.name}: could not be executed."
        )

    try:
        doc = _json.loads(inv.stdout)
    except (ValueError, _json.JSONDecodeError):
        return CommercialScanResult(
            status="unavailable", notes=f"{spec.name}: produced no parseable JSON."
        )

    normalizer = spec.normalizer
    if normalizer is None:  # pragma: no cover — registry guarantees a normalizer
        return CommercialScanResult(
            status="unavailable", notes=f"{spec.name}: no normalizer wired."
        )

    try:
        tool_findings = normalizer(
            doc,
            source_tool=spec.name,
            default_dimension=spec.default_dimension,
        )
    except Exception as exc:  # noqa: BLE001 — D-25 boundary: never raise
        return CommercialScanResult(
            status="unavailable",
            notes=f"{spec.name}: normalize failed: {type(exc).__name__}: {exc}",
        )

    return CommercialScanResult(
        findings=tool_findings,
        status="ok",
        notes=f"{spec.name}: {len(tool_findings)} finding(s).",
    )


def _derive_status(statuses: list[str]) -> CommercialStatus:
    """All-ok → ok / some-ok → partial / none → unavailable (mirror run_mobile)."""
    if statuses and all(s == "ok" for s in statuses):
        return "ok"
    if any(s == "ok" for s in statuses):
        return "partial"
    return "unavailable"


__all__ = [
    "COMMERCIAL_TOOLS",
    "CommercialScanResult",
    "run_byo_commercial",
]
