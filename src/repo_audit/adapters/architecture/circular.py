"""ARCH-01 — dependency-cruiser circular-dep / boundary-violation collector (Phase 14, Plan 02).

``collect_dependency_cruiser`` is the never-raising, JS/TS-gated collection function
that invokes dependency-cruiser through the shared ``run_tool`` seam, parses its
NATIVE JSON reporter output (dependency-cruiser has NO SARIF reporter — D-14-04 /
Pitfall 1), and maps each ``summary.violations[]`` entry to one ``architecture_rot``
Finding via :func:`depcruise_json.depcruise_summary_to_findings` (NOT
``sarif_to_findings``).

It follows the canonical five-gate ``collect_checkov`` shape (``adapters/cicd/iac.py``),
in order:

    GATE 1 — has_js_dependency_graph FIRST. On a non-JS stack (or a repo with no
        ``package.json`` JS-graph signal) → ``status='not_applicable'`` WITHOUT
        invoking dependency-cruiser (the first-class not-applicable degrade,
        RESEARCH Discretion #5). When the caller supplies ``stacks`` we gate on the
        detector's tags; when it does not (the standalone-collector path the Wave-1
        tests exercise) we fall back to the ``package.json`` filesystem signal.
    GATE 2 — resolve_tool("depcruise", repo) with the DEFAULT ``trusted_only=False``.
        A ``None`` → ``status='unavailable'``, tool NOT invoked.
    GATE 3 — build the argv. When the repo brings its own ``.dependency-cruiser.*``,
        pass NO ``--config`` (auto-discovery, Pitfall 5). A zero-config repo gets the
        SHIPPED MINIMAL RULESET (no-circular + not-to-unresolvable + not-to-dev-dep
        ONLY; NO no-orphans, NO layering — D-14-02) written to a ``scan_tempdir()``
        file and passed via ``--config <tempfile>``.
    GATE 4 — map the run_tool sentinels: TIMED_OUT (-2) → ``status='timeout'``;
        EXEC_FAILED (-1) → ``status='unavailable'``.
    GATE 5 — gate on PARSE, not returncode (Pitfall 4): dependency-cruiser exits
        non-zero WHEN it finds violations, so the JSON on stdout is the real signal.
        A ``json.loads`` failure → ``status='unavailable'`` (never raises); a valid
        document → ``findings = depcruise_summary_to_findings(...)``, ``status='ok'``.

**resolve_tool posture (T-14-02-02, deliberate):** dependency-cruiser is an npm
PROJECT tool (the knip/tsc/eslint precedent), so this collector uses the DEFAULT
``trusted_only=False`` — the ``node_modules/.bin`` walk-up IS the intended T-03-03
mitigation here. This is INTENTIONALLY distinct from the ``trusted_only=True``
security-scanner posture (osv-scanner / semgrep / checkov); it is not an oversight.

``resolve_tool`` and ``run_tool`` are re-exported as module-level names so the
absent-binary / timeout / parse tests can ``monkeypatch.setattr(circular, …)``.

``default_dimension``, ``severity_map`` and ``timeout_ms`` are resolved from
``adapter.yaml`` at CALL time (the Phase 3 no-module-load-caching lesson), with
documented module-level fallback constants if the depcruise block is absent.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

from ruamel.yaml import YAML

from repo_audit.adapters.architecture.depcruise_json import (
    depcruise_summary_to_findings,
)
from repo_audit.adapters.architecture.detect import has_js_dependency_graph
from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

CircularStatus = Literal["ok", "unavailable", "timeout", "not_applicable"]

# Fallbacks used only if adapter.yaml is unreadable / the depcruise block is
# absent — the descriptor is the source of truth at call time.
_DEPCRUISE_DEFAULT_DIMENSION = "architecture_rot"
_DEPCRUISE_DEFAULT_TIMEOUT = 120.0
_DEPCRUISE_TOOL = "depcruise"

# The repo's own config — when present, depcruise auto-discovers it and we pass NO
# --config (Pitfall 5). The standard dependency-cruiser config filename variants.
_REPO_CONFIG_GLOBS = (
    ".dependency-cruiser.js",
    ".dependency-cruiser.cjs",
    ".dependency-cruiser.mjs",
    ".dependency-cruiser.json",
)

# The JS-graph filesystem signal used by the standalone-collector path (no `stacks`
# supplied): a package.json means a JS/Node dependency graph is present.
_JS_GRAPH_MANIFEST = "package.json"

# SHIPPED MINIMAL ZERO-CONFIG RULESET (RESEARCH lines 426-440, schema-validated live).
# no-circular + not-to-unresolvable + not-to-dev-dep ONLY — NO no-orphans, NO layering
# (D-14-02): high-precision structural signal, never the orphan/layering flood.
_MINIMAL_RULESET: dict[str, Any] = {
    "forbidden": [
        {
            "name": "no-circular",
            "comment": "circular dependency chain",
            "severity": "error",
            "from": {},
            "to": {"circular": True},
        },
        {
            "name": "not-to-unresolvable",
            "comment": "broken/dangling import",
            "severity": "error",
            "from": {},
            "to": {"couldNotResolve": True},
        },
        {
            "name": "not-to-dev-dep",
            "comment": "prod code importing a devDependency",
            "severity": "error",
            "from": {"path": "^(src|lib|app)", "pathNot": "\\.(spec|test)\\."},
            "to": {"dependencyTypes": ["npm-dev"]},
        },
    ]
}

# Paths a zero-config cruise never enters: installed dependencies, build output,
# and dot-directories (tooling state, scratch, templates that are not real modules).
_EXCLUDE_PATH = "(^|/)(node_modules|dist|build|coverage|\\.[^/]+)/"

# Conventional JS/TS source directories, cruised when present. One unparseable
# stray file anywhere under ``.`` aborts the whole cruise, so ``.`` is the
# fallback only when none of these exist.
_SOURCE_DIRS = (
    "src",
    "app",
    "lib",
    "components",
    "packages",
    "pages",
    "screens",
    "hooks",
    "utils",
    "services",
    "features",
    "modules",
    "server",
    "client",
    "store",
)


@dataclass
class CircularResult:
    """Never-raise envelope for :func:`collect_dependency_cruiser`.

    Mirrors the cicd ``CheckovResult`` envelope: every failure mode (non-JS stack,
    absent binary, exec-failure, timeout, malformed JSON) folds into ``status`` +
    ``notes`` rather than raised. ``status='ok'`` carries the architecture_rot
    static/candidate findings; ``not_applicable`` is the no-JS-graph degrade.
    """

    findings: list[Finding] = field(default_factory=list)
    status: CircularStatus = "ok"
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


def _depcruise_config() -> dict:
    """Return the depcruise per-tool block from ``adapter.yaml`` (empty if absent)."""
    cfg = _load_arch_config()
    return (cfg.get("tools") or {}).get("depcruise") or {}


def _has_repo_config(repo_path: Path) -> bool:
    """True iff the repo brings its own ``.dependency-cruiser.*`` (Pitfall 5)."""
    return any((repo_path / name).is_file() for name in _REPO_CONFIG_GLOBS)


def _is_js_applicable(repo_path: Path, stacks: Iterable[str] | None) -> bool:
    """GATE 1 predicate — is the architecture step applicable to this repo?

    When ``stacks`` is supplied (the Plan-04 composed path) we gate on the detector's
    tags via :func:`has_js_dependency_graph`. When ``stacks`` is ``None`` (the
    standalone-collector path the Wave-1 tests exercise) we fall back to the
    ``package.json`` JS-graph filesystem signal — a repo with a ``package.json`` has
    an analyzable JS/Node dependency graph.
    """
    if stacks is not None:
        return has_js_dependency_graph(stacks)
    return (repo_path / _JS_GRAPH_MANIFEST).is_file()


def _source_roots(repo_path: Path) -> list[str]:
    """The conventional source directories the repo has, else the repo root.

    An Expo or React Native app keeps its code in ``app/``, ``lib/`` and
    ``components/``; cruising a missing ``src`` makes depcruise exit with no JSON.
    """
    roots = [d for d in _SOURCE_DIRS if (repo_path / d).is_dir()]
    return roots or ["."]


def _shipped_config(repo_path: Path) -> dict[str, Any]:
    """The minimal ruleset plus the options a zero-config cruise needs on a real repo.

    Without ``doNotFollow``/``exclude`` depcruise walks into node_modules (cycles
    inside dependencies, and a stack overflow on React Native's bundled
    JavaScript); without ``tsConfig`` every tsconfig path alias reads as
    unresolvable. ``tsConfig`` is passed only when dependencies are installed:
    a tsconfig usually extends a package, and an unloadable one aborts the run.
    """
    options: dict[str, Any] = {
        "doNotFollow": {"path": "node_modules"},
        "exclude": {"path": _EXCLUDE_PATH},
        "tsPreCompilationDeps": True,
    }
    if (repo_path / "tsconfig.json").is_file() and (
        repo_path / "node_modules"
    ).is_dir():
        options["tsConfig"] = {"fileName": "tsconfig.json"}
    return {**_MINIMAL_RULESET, "options": options}


def _depcruise_argv(
    binary: Path, shipped_config: Path | None, source_roots: list[str]
) -> list[str]:
    """Build the EXACT depcruise argv (list[str], shell=False guard; RESEARCH line 507).

    ``--output-type json`` is the only reporter (no SARIF — D-14-04). When the repo
    has its own config we pass NO ``--config`` (auto-discovery, Pitfall 5); a
    zero-config repo gets ``--config <shipped tempfile>``. ``source_roots`` come
    from :func:`_source_roots`; each token is a DISCRETE argv element (T-14-02-01 —
    never interpolated into a shell string).
    """
    argv = [str(binary), "--output-type", "json"]
    if shipped_config is not None:
        argv += ["--config", str(shipped_config)]
    argv += source_roots
    return argv


def collect_dependency_cruiser(
    repo_path: Path,
    env: dict[str, str],
    *,
    stacks: Iterable[str] | None = None,
    timeout_seconds: float | None = None,
) -> CircularResult:
    """Run dependency-cruiser over the repo and return architecture_rot findings.

    Args:
        repo_path: the target repository root.
        env: the child environment (cache-redirected by the caller).
        stacks: the detector's stack tags. When supplied, GATE 1 uses
            :func:`has_js_dependency_graph`; when ``None`` (the standalone path),
            GATE 1 falls back to the ``package.json`` filesystem signal.
        timeout_seconds: hard wall-clock bound; defaults to the ``adapter.yaml``
            depcruise ``timeout_ms`` (120s — OUTSIDE the 95s collector deadline).

    Returns:
        A :class:`CircularResult`. ``status='ok'`` with architecture_rot
        static/candidate findings on success; ``status='not_applicable'`` on a
        non-JS repo (tool NOT invoked); ``status='unavailable'`` when depcruise is
        absent, exec-failed, or its output is unparseable; ``status='timeout'`` on
        expiry. NEVER raises, NEVER hangs.
    """
    repo_path = Path(repo_path)
    cfg = _depcruise_config()
    default_dimension = cfg.get("default_dimension", _DEPCRUISE_DEFAULT_DIMENSION)
    severity_map = cfg.get("severity_map") or None
    if timeout_seconds is None:
        timeout_ms = cfg.get("timeout_ms")
        timeout_seconds = (
            float(timeout_ms) / 1000.0 if timeout_ms else _DEPCRUISE_DEFAULT_TIMEOUT
        )

    # GATE 1 — no JS dependency graph is a first-class not-applicable degrade.
    # dependency-cruiser is NEVER invoked on a non-JS repo (RESEARCH Discretion #5).
    if not _is_js_applicable(repo_path, stacks):
        return CircularResult(
            status="unavailable",
            notes="no JS/TS dependency graph — dependency-cruiser not applicable",
        )

    # GATE 2 — DEFAULT trusted_only=False (T-14-02-02): dependency-cruiser is an npm
    # PROJECT tool (knip/tsc/eslint precedent); the node_modules/.bin walk-up IS the
    # intended T-03-03 mitigation. Deliberately NOT the security-scanner posture.
    binary = resolve_tool(_DEPCRUISE_TOOL, repo_path)
    if binary is None:
        return CircularResult(
            status="unavailable",
            notes="dependency-cruiser (depcruise) not found (node_modules + PATH miss)",
        )

    with ExitStack() as stack:
        # GATE 3 — config handling (Pitfall 5). Repo brings its own config -> NO
        # --config (auto-discovery). Zero-config -> write the SHIPPED MINIMAL RULESET
        # to a scan_tempdir() file (OUTSIDE the read-only repo, REP-03) + --config it.
        shipped_config: Path | None = None
        if not _has_repo_config(repo_path):
            tmp_dir = stack.enter_context(scan_tempdir())
            shipped_config = tmp_dir / "minimal.dependency-cruiser.json"
            shipped_config.write_text(
                json.dumps(_shipped_config(repo_path), indent=2) + "\n",
                encoding="utf-8",
            )

        invocation = run_tool(
            _depcruise_argv(binary, shipped_config, _source_roots(repo_path)),
            env=dict(env),
            cwd=repo_path,
            timeout_seconds=timeout_seconds,
        )

        # GATE 4 — run_tool structural sentinels (these NEVER raise).
        if invocation.returncode == TIMED_OUT:
            return CircularResult(
                status="timeout",
                notes=f"dependency-cruiser exceeded {timeout_seconds:.0f}s",
            )
        if invocation.returncode == EXEC_FAILED:
            return CircularResult(
                status="unavailable",
                notes=f"dependency-cruiser could not be executed: {invocation.stderr}",
            )

        # GATE 5 — gate on PARSE, not returncode (Pitfall 4): dependency-cruiser exits
        # non-zero when it finds violations, so the JSON on stdout is the real signal.
        # Malformed JSON -> unavailable (never raises).
        try:
            doc = json.loads(invocation.stdout)
            summary = (doc or {}).get("summary") or {}
            if summary.get("totalCruised") == 0:
                # An empty graph is not a clean result: depcruise read nothing,
                # typically TypeScript it could not parse (it supports < 7).
                return CircularResult(
                    status="unavailable",
                    notes=(
                        "dependency-cruiser analyzed 0 modules — it could not "
                        "read the source (TypeScript needs a TypeScript older "
                        "than 7 that dependency-cruiser can load)"
                    ),
                )
            violations = summary.get("violations") or []
            findings = depcruise_summary_to_findings(
                violations,
                default_dimension=default_dimension,
                severity_map=severity_map,
            )
        except Exception as exc:  # noqa: BLE001 — never raise across the boundary
            return CircularResult(
                status="unavailable",
                notes=f"dependency-cruiser JSON parse failed: {type(exc).__name__}: {exc}",
            )

        cruised = summary.get("totalCruised")
        across = f" across {cruised} module(s)" if isinstance(cruised, int) else ""
        return CircularResult(
            findings=findings,
            status="ok",
            notes=f"dependency-cruiser: {len(findings)} violation finding(s){across}",
        )


__all__ = [
    "CircularResult",
    "collect_dependency_cruiser",
    "resolve_tool",
    "run_tool",
]
