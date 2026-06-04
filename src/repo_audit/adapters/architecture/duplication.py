"""ARCH-02 — jscpd copy-paste duplication collector (Phase 14, Plan 03).

``collect_jscpd`` is the never-raising, REPO-WIDE (polyglot, NOT stack-gated —
D-14-01) collection function that invokes jscpd through the shared ``run_tool``
seam, writes the JSON report to a ``scan_tempdir()`` OUTSIDE the read-only target
repo, reads that report **FILE** (NOT stdout — Pitfall 2), and maps
``statistics.total`` to **exactly ONE** aggregate ``architecture_rot`` Finding via
:func:`jscpd_json.map_jscpd_json` (the SC2-authorized counted summary, deliberately
NOT a per-clone-pair flood — D-14-03).

It follows the canonical write-to-tempdir-outside-repo-then-read-FILE shape of
``adapters/cicd/iac.py::collect_checkov``, in gate order:

    GATE 1 — none. Duplication is repo-wide and language-agnostic (D-14-01); jscpd
        runs on every repo (it tokenizes whatever languages it finds). There is no
        not-applicable degrade — a repo with no duplication simply returns a
        below-floor result (0 findings, the % in the notes).
    GATE 2 — resolve_tool("jscpd", repo) with the DEFAULT ``trusted_only=False``.
        A ``None`` → ``status='unavailable'``, ``run_tool`` NOT invoked.
    GATE 3 — build the argv to a ``scan_tempdir()`` ``--output`` dir GUARANTEED
        outside the repo. A PRIMARY containment guard (``_is_under``) refuses any
        out_dir under the read-only target before jscpd is invoked (REP-03 / V12).
        ``--ignore`` globs are built from ``DEFAULT_SKIP_DIRS`` (Pitfall 7).
        ``--threshold`` is NOT passed (Pitfall 4 — keep exit 0 / gate-on-parse).
    GATE 4 — map the run_tool sentinels: TIMED_OUT (-2) → ``status='timeout'``;
        EXEC_FAILED (-1) → ``status='unavailable'``.
    GATE 5 — read + parse ``<out_dir>/jscpd-report.json`` (the FILE, NOT stdout —
        Pitfall 2). A missing file / malformed JSON → ``status='unavailable'``
        (never raises). A valid document → ``findings = map_jscpd_json(report,
        floor_pct=<cfg>, top_n=<cfg>)``, ``status='ok'``. When below the floor (0
        findings) the result ``notes`` carry the duplication % so the number still
        surfaces in the scope summary (SAFE-08).

**resolve_tool posture (T-14-03-03, deliberate):** jscpd is an npm PROJECT tool
(the knip/tsc/eslint/dependency-cruiser precedent), so this collector uses the
DEFAULT ``trusted_only=False`` — the ``node_modules/.bin`` walk-up IS the intended
T-03-03 mitigation here. This is INTENTIONALLY distinct from the
``trusted_only=True`` security-scanner posture (osv-scanner / semgrep / checkov);
it is not an oversight.

``resolve_tool`` and ``run_tool`` are re-exported as module-level names so the
absent-binary / timeout / parse tests can ``monkeypatch.setattr(duplication, …)``.

``floor_pct`` / ``top_n`` / ``min_tokens`` / ``min_lines`` / ``timeout_ms`` /
``default_dimension`` are resolved from ``adapter.yaml`` at CALL time (the Phase 3
no-module-load-caching lesson), then layered over by the per-repo
``.repo-audit.yaml`` ``architecture.duplication`` override (SC4) — also read
at CALL time. Documented module-level fallback constants apply if a descriptor is
unreadable.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml import YAML

from repo_audit.adapters.architecture.jscpd_json import map_jscpd_json
from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding
from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS

DuplicationStatus = Literal["ok", "unavailable", "timeout"]

# Fallbacks used only if adapter.yaml is unreadable / the jscpd block is absent —
# the descriptor is the source of truth at call time.
_JSCPD_DEFAULT_DIMENSION = "architecture_rot"
_JSCPD_DEFAULT_TIMEOUT = 120.0
_JSCPD_DEFAULT_FLOOR_PCT = 5
_JSCPD_DEFAULT_MIN_TOKENS = 50
_JSCPD_DEFAULT_MIN_LINES = 5
_JSCPD_DEFAULT_TOP_N = 10
_JSCPD_TOOL = "jscpd"

# jscpd writes its JSON report here inside the --output dir (Pitfall 2).
_REPORT_FILENAME = "jscpd-report.json"


@dataclass
class DuplicationResult:
    """Never-raise envelope for :func:`collect_jscpd`.

    Mirrors the cicd ``CheckovResult`` / architecture ``CircularResult`` envelope:
    every failure mode (absent binary, out_dir-under-repo, exec-failure, timeout,
    missing/malformed report file) folds into ``status`` + ``notes`` rather than
    raised. ``status='ok'`` carries the architecture_rot static/candidate finding
    (or ``[]`` below the reporting floor — with the % surfaced in ``notes``).
    """

    findings: list[Finding] = field(default_factory=list)
    status: DuplicationStatus = "ok"
    notes: str = ""


def _load_arch_config() -> dict:
    """Load the architecture ``adapter.yaml`` via the safe YAML loader (T-03-01).

    Resolved at CALL time (no module-load caching — the Phase 3 lesson). Returns an
    empty dict on any read/parse failure so the collector falls back to its
    documented defaults rather than raising.
    """
    try:
        yaml = YAML(typ="safe")
        with (Path(__file__).parent / "adapter.yaml").open(encoding="utf-8") as fh:
            return yaml.load(fh) or {}
    except Exception:  # noqa: BLE001 — descriptor read must never break a scan
        return {}


def _jscpd_config() -> dict:
    """Return the jscpd per-tool block from ``adapter.yaml`` (empty if absent)."""
    cfg = _load_arch_config()
    return (cfg.get("tools") or {}).get("jscpd") or {}


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``architecture.duplication`` block.

    Read at CALL time (SC4): a repo may override ``floor_pct`` (and the other
    thresholds) without touching the shipped descriptor. Returns an empty dict when
    the file is absent / unreadable / has no ``architecture.duplication`` block, so
    the adapter.yaml defaults stand. NEVER raises (a malformed user YAML must not
    break a scan).
    """
    override_file = repo_path / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        arch = (doc.get("architecture") or {}).get("duplication") or {}
        return arch if isinstance(arch, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def _resolve_int(blocks: list[dict], key: str, default: int) -> int:
    """Resolve an int threshold, later blocks (repo override) winning over earlier."""
    value = default
    for block in blocks:
        if key in block and block[key] is not None:
            value = block[key]
    return value


def _ignore_globs() -> str:
    """Build the jscpd ``--ignore`` value from ``DEFAULT_SKIP_DIRS`` (Pitfall 7).

    One comma-joined ``**/{dir}/**`` glob per well-known skip dir (node_modules,
    .git, dist, build, …). The globs are STATIC (built from the in-package
    constant, never from untrusted repo paths — FND-04 / T-14-03-01), so no hostile
    repo filename crosses into the glob string.
    """
    return ",".join(f"**/{d}/**" for d in DEFAULT_SKIP_DIRS)


def _jscpd_argv(
    binary: Path,
    out_dir: Path,
    *,
    min_tokens: int,
    min_lines: int,
) -> list[str]:
    """Build the EXACT jscpd argv (list[str], shell=False guard; RESEARCH 491-502).

    ``--reporters json`` + ``--output <out_dir>`` route the report to the FILE
    ``<out_dir>/jscpd-report.json`` (Pitfall 2) — NOT stdout, which is banner noise.
    ``--silent`` quiets the banner. ``--min-tokens`` / ``--min-lines`` set the clone
    detection floor. ``--ignore <globs>`` bounds the scan (Pitfall 7). The final
    ``.`` is the scan root (cwd=repo). ``--threshold`` is DELIBERATELY NOT passed
    (Pitfall 4) so jscpd exits 0 and the gate is parse-of-FILE, never returncode.
    Each token is a DISCRETE argv element (T-14-03-01 — never shell-interpolated).
    """
    return [
        str(binary),
        "--reporters",
        "json",
        "--output",
        str(out_dir),
        "--silent",
        "--min-tokens",
        str(min_tokens),
        "--min-lines",
        str(min_lines),
        "--ignore",
        _ignore_globs(),
        ".",
    ]


def _is_under(child: Path, parent: Path) -> bool:
    """True iff ``child`` resolves to ``parent`` or one of its descendants.

    Boundary-safe containment check (NOT a string-prefix test, which would treat a
    sibling ``/repo-2`` as inside ``/repo``). Used as the PRIMARY read-only guard:
    the jscpd out_dir must NOT be under the scanned repo (REP-03 / T-14-03-02).
    """
    child_r = child.resolve()
    parent_r = parent.resolve()
    return child_r == parent_r or parent_r in child_r.parents


def collect_jscpd(
    repo_path: Path,
    env: dict[str, str],
    *,
    timeout_seconds: float | None = None,
    out_dir: Path | None = None,
) -> DuplicationResult:
    """Run jscpd repo-wide and return the single aggregate duplication finding.

    Args:
        repo_path: the target repository root.
        env: the child environment (cache-redirected by the caller).
        timeout_seconds: hard wall-clock bound; defaults to the ``adapter.yaml``
            jscpd ``timeout_ms`` (120s — OUTSIDE the 95s collector deadline).
        out_dir: where jscpd writes ``jscpd-report.json``. When ``None``, a tempdir
            under ``scan_tempdir()`` is used — GUARANTEED outside ``repo_path``
            (REP-03). A supplied out_dir is refused if it is under the repo.

    Returns:
        A :class:`DuplicationResult`. ``status='ok'`` with the single
        architecture_rot static/candidate finding (or ``[]`` below the floor, the %
        in ``notes``) on success; ``status='unavailable'`` when jscpd is absent /
        exec-failed, the out_dir is under the repo, or the report file is
        missing/malformed; ``status='timeout'`` on expiry. NEVER raises, NEVER hangs.
    """
    repo_path = Path(repo_path)
    cfg = _jscpd_config()
    override = _load_repo_override(repo_path)  # SC4 per-repo override (call-time)
    blocks = [cfg, override]  # override wins (later in the list)

    default_dimension = override.get(
        "default_dimension", cfg.get("default_dimension", _JSCPD_DEFAULT_DIMENSION)
    )
    floor_pct = _resolve_int(blocks, "floor_pct", _JSCPD_DEFAULT_FLOOR_PCT)
    top_n = _resolve_int(blocks, "top_n_hotspots", _JSCPD_DEFAULT_TOP_N)
    min_tokens = _resolve_int(blocks, "min_tokens", _JSCPD_DEFAULT_MIN_TOKENS)
    min_lines = _resolve_int(blocks, "min_lines", _JSCPD_DEFAULT_MIN_LINES)
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _JSCPD_DEFAULT_TIMEOUT
        )

    # GATE 1 — NONE. Duplication is repo-wide + language-agnostic (D-14-01); jscpd
    # runs on every repo. No not-applicable degrade.

    # GATE 2 — DEFAULT trusted_only=False (T-14-03-03): jscpd is an npm PROJECT tool
    # (knip/dependency-cruiser precedent); the node_modules/.bin walk-up IS the
    # intended T-03-03 mitigation. Deliberately NOT the security-scanner posture.
    binary = resolve_tool(_JSCPD_TOOL, repo_path)
    if binary is None:
        return DuplicationResult(
            status="unavailable",
            notes="jscpd not found (node_modules + PATH miss)",
        )

    with ExitStack() as stack:
        # GATE 3 — the report output dir MUST live OUTSIDE the read-only target
        # (REP-03 / T-14-03-02). When the caller did not supply one, create a
        # tempdir under scan_tempdir() whose lifecycle is tied to this call.
        if out_dir is None:
            out_dir = stack.enter_context(scan_tempdir())
        else:
            out_dir = Path(out_dir)

        # PRIMARY read-only guard (defense-in-depth ahead of the Plan-04 post-flight
        # diff_git_status backstop): the report dir must NOT be under the scanned
        # repo. Refuse rather than risk a target-repo write.
        if _is_under(out_dir, repo_path):
            return DuplicationResult(
                status="unavailable",
                notes=(
                    "refusing to write jscpd report under the scanned repo "
                    "(read-only contract); out_dir must live outside the target tree"
                ),
            )
        out_dir.mkdir(parents=True, exist_ok=True)

        invocation = run_tool(
            _jscpd_argv(
                binary, out_dir, min_tokens=min_tokens, min_lines=min_lines
            ),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 4 — run_tool structural sentinels (these NEVER raise).
        if invocation.returncode == TIMED_OUT:
            return DuplicationResult(
                status="timeout",
                notes=f"jscpd exceeded {timeout_seconds:.0f}s",
            )
        if invocation.returncode == EXEC_FAILED:
            return DuplicationResult(
                status="unavailable",
                notes=f"jscpd could not be executed: {invocation.stderr}",
            )

        # GATE 5 — read + parse the report FILE, NOT stdout (Pitfall 2): stdout is
        # banner noise. A missing file / malformed JSON → unavailable (never raises).
        # --threshold is not passed, so jscpd exits 0 and the gate is parse-of-FILE.
        report_file = out_dir / _REPORT_FILENAME
        if not report_file.is_file():
            return DuplicationResult(
                status="unavailable",
                notes="jscpd produced no report file",
            )

        try:
            report = json.loads(report_file.read_text(encoding="utf-8"))
            findings = map_jscpd_json(
                report,
                default_dimension=default_dimension,
                floor_pct=floor_pct,
                top_n=top_n,
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return DuplicationResult(
                status="unavailable",
                notes=f"jscpd report parse failed: {type(exc).__name__}: {exc}",
            )

        # SAFE-08: even below the floor (0 findings) the duplication % must surface
        # in the scope summary, so stamp it into the notes from statistics.total.
        overall_pct = _overall_pct(report)
        if findings:
            notes = f"jscpd: {overall_pct}% duplicated lines (1 aggregate finding)"
        else:
            notes = (
                f"jscpd: {overall_pct}% duplicated lines "
                f"(below floor {floor_pct}% — no finding)"
            )

        return DuplicationResult(findings=findings, status="ok", notes=notes)


def _overall_pct(report: dict[str, Any]) -> Any:
    """The headline duplicated-LINES % from ``statistics.total`` (or ``'?'``)."""
    total = ((report or {}).get("statistics") or {}).get("total") or {}
    pct = total.get("percentage")
    return pct if pct is not None else "?"


__all__ = [
    "DuplicationResult",
    "collect_jscpd",
    "resolve_tool",
    "run_tool",
]
