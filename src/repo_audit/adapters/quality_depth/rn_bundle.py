"""PERF-01 RN tier — JS-bundle-size collector + aggregate mapper (Phase 15, Plan 03).

``collect_rn_bundle`` measures the production React-Native JS bundle size and
collapses it to ONE aggregate ``quality`` size Finding (+ independent
oversized/regression triggers) via :func:`map_rn_bundle_bytes` (the jscpd / lcov
single-aggregate model — ``evidence_type='static'`` here: a measured artifact, NOT
a runtime page load).

TWO measurement paths, in order:

    PATH A — EXISTING ARTIFACT (default, ``qd_build=False``). Glob the repo's
        build dirs for an existing ``index.android.bundle`` / ``*.jsbundle``. If
        one is present, ``stat().st_size`` it — NO build, zero subprocess. If
        absent → ``status='unavailable'`` (SAFE-08: the build is opt-in; absent
        opt-in + absent artifact → honest degrade).

    PATH B — OPT-IN THROWAWAY BUILD (``qd_build=True``). The MOB-03
        ``diagnostic_build.py`` THROWAWAY-COPY pattern, never in-place:
          (1) ``snapshot_git_status`` the ORIGINAL tree (the MOD-1 baseline).
          (2) ``git archive HEAD`` → tarball → ``tar -xf`` into a
              ``scan_tempdir()`` copy (tracked files only; no .git, no cruft);
              ``cp -al`` node_modules in (Metro needs it; git archive omits it).
          (3) ``react-native bundle --dev false`` runs in the COPY (``cwd=work``),
              ``--bundle-output`` redirected to the tempdir — never the target
              repo; ``stat().st_size`` the produced bundle.
          (4) MOD-1 BACKSTOP: re-snapshot + ``diff_git_status`` the ORIGINAL tree.
              ANY offender → ``status='unavailable'`` with a MOD-1 note, NEVER a
              size from a dirtying run (T-15-09 read-only invariant).

CONTAINMENT (T-15-09): the build cwd is ALWAYS the tempdir copy, NEVER the target
tree; the output bundle is written under the tempdir; ``_is_under`` (the
architecture containment guard) refuses any out_dir under the repo. ``--dev false``
is MANDATORY (the production bundle size, RESEARCH Pattern 4).

ALL subprocess work goes through the shared ``run_tool`` seam — this module NEVER
imports ``subprocess`` directly. ``resolve_tool`` / ``run_tool`` /
``snapshot_git_status`` / ``diff_git_status`` are re-exported as module-level names
so the absent-binary / dirtying-build / timeout tests can
``monkeypatch.setattr(rn_bundle, …)`` host-independently (no real Metro, no real
git state).
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from repo_audit.adapters.architecture.duplication import _is_under
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.quality_depth.rn_bundle_json import map_rn_bundle_bytes
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.schema.finding import Finding

if TYPE_CHECKING:
    from repo_audit.adapters.quality_depth.config import QualityDepthConfig

RnBundleStatus = Literal["ok", "unavailable", "timeout"]

_REACT_NATIVE_TOOL = "react-native"

# MOB-03 900s override — a cold Metro bundle build is slow. git archive / tar /
# cp get short bounds.
_BUILD_TIMEOUT_SECONDS: float = 900.0
_ARCHIVE_TIMEOUT_SECONDS: float = 120.0
_COPY_TIMEOUT_SECONDS: float = 300.0

# How many chars of a failing tool's stderr we surface (bounded).
_STDERR_TAIL_CHARS: int = 600

# Existing-artifact glob names (PATH A). Android Metro bundle + the generic iOS
# / Expo jsbundle. We search the repo recursively under common build roots.
_BUNDLE_GLOBS: tuple[str, ...] = ("index.android.bundle", "*.jsbundle")


@dataclass
class RnBundleResult:
    """Never-raise envelope for :func:`collect_rn_bundle`.

    Mirrors the quality_depth ``LighthouseResult`` / mobile ``BuildResult``
    envelope: every failure mode (no artifact + no build, absent binary,
    exec-failure, timeout, MOD-1 tripwire) folds into ``status`` + ``notes``
    rather than raised. ``status='ok'`` carries the aggregate static size finding.
    """

    findings: list[Finding] = field(default_factory=list)
    status: RnBundleStatus = "ok"
    notes: str = ""


def _tail(text: str) -> str:
    """Return the last ``_STDERR_TAIL_CHARS`` chars of ``text`` (bounded)."""
    text = (text or "").strip()
    if len(text) <= _STDERR_TAIL_CHARS:
        return text
    return "…" + text[-_STDERR_TAIL_CHARS:]


def _find_existing_bundle(repo_path: Path) -> Path | None:
    """Glob the repo for an existing production bundle artifact (PATH A).

    Returns the first match (a stable, already-built artifact) or ``None``. We
    rglob the whole tree for the well-known names; node_modules is skipped so a
    vendored fixture bundle inside a dependency never masquerades as the app's.
    """
    for pattern in _BUNDLE_GLOBS:
        for candidate in repo_path.rglob(pattern):
            if "node_modules" in candidate.parts:
                continue
            if candidate.is_file():
                return candidate
    return None


def collect_rn_bundle(
    repo_path: Path,
    env: dict[str, str],
    *,
    qd_build: bool,
    config: "QualityDepthConfig | None" = None,
    prior_rn_bytes: int | None = None,
    timeout_seconds: float | None = None,
) -> RnBundleResult:
    """Measure the RN production JS-bundle size; return the aggregate size finding.

    Args:
        repo_path: the target repository root (read-only; NEVER the build cwd).
        env: the child environment (cache-redirected by the caller).
        qd_build: the opt-in flag for the throwaway Metro build (PATH B). When
            ``False`` (default) and no existing artifact is present → SAFE-08
            ``unavailable``, no build.
        config: the resolved :class:`QualityDepthConfig` (budget + regression).
            ``None`` → the documented defaults.
        prior_rn_bytes: an optional prior-scan ``rn_bundle_bytes`` baseline
            forwarded to the mapper's regression trigger (None → baseline run).
        timeout_seconds: hard wall-clock bound on the Metro build; defaults to the
            MOB-03 900s override.

    Returns:
        An :class:`RnBundleResult`. ``status='ok'`` with the aggregate static size
        finding(s) on success; ``status='unavailable'`` when there is no artifact
        and no opt-in build, react-native is absent, the build fails, or the MOD-1
        tripwire fires; ``status='timeout'`` on expiry. NEVER raises, NEVER hangs,
        NEVER returns a size from a run that dirtied the target tree.
    """
    repo_path = Path(repo_path)
    if timeout_seconds is None:
        timeout_seconds = _BUILD_TIMEOUT_SECONDS
    if config is None:
        from repo_audit.adapters.quality_depth.config import QualityDepthConfig

        config = QualityDepthConfig()

    # PATH A — existing artifact (default, no build).
    existing = _find_existing_bundle(repo_path)
    if existing is not None:
        size = existing.stat().st_size
        findings = map_rn_bundle_bytes(
            size, config=config, prior_rn_bytes=prior_rn_bytes
        )
        return RnBundleResult(
            findings=findings,
            status="ok",
            notes=f"rn_bundle: measured existing artifact {existing.name} ({size} bytes)",
        )

    if not qd_build:
        # SAFE-08: no opt-in build AND no existing artifact → honest degrade.
        return RnBundleResult(
            status="unavailable",
            notes=(
                "no existing RN bundle artifact and --qd-build not set — "
                "RN bundle size skipped (SAFE-08; the build is opt-in)"
            ),
        )

    # PATH B — opt-in throwaway Metro build.
    return _build_and_measure(
        repo_path,
        env,
        config=config,
        prior_rn_bytes=prior_rn_bytes,
        timeout_seconds=timeout_seconds,
    )


def _build_and_measure(
    repo_path: Path,
    env: dict[str, str],
    *,
    config: "QualityDepthConfig",
    prior_rn_bytes: int | None,
    timeout_seconds: float,
) -> RnBundleResult:
    """The throwaway-copy Metro build path with the MOD-1 backstop (PATH B)."""
    # (1) MOD-1 baseline on the ORIGINAL tree, taken BEFORE any work.
    pre = snapshot_git_status(repo_path)

    try:
        result = _build_in_tempdir(
            repo_path,
            env,
            config=config,
            prior_rn_bytes=prior_rn_bytes,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — never-raise backstop
        result = RnBundleResult(
            status="unavailable",
            notes=f"rn bundle build raised unexpectedly: {type(exc).__name__}: {exc}",
        )

    # (2) MOD-1 BACKSTOP: re-snapshot + diff the ORIGINAL tree. ANY offender →
    #     a copy leaked (a bug) — self-report unavailable, NEVER return a size.
    offenders = diff_git_status(pre, snapshot_git_status(repo_path))
    if offenders:
        return RnBundleResult(
            status="unavailable",
            notes=(
                "MOD-1 tripwire fired (rn bundle build leaked into the target "
                f"tree): {offenders}"
            ),
        )

    return result


def _build_in_tempdir(
    repo_path: Path,
    env: dict[str, str],
    *,
    config: "QualityDepthConfig",
    prior_rn_bytes: int | None,
    timeout_seconds: float,
) -> RnBundleResult:
    """The throwaway-copy build body (no tripwire — the caller owns that)."""
    binary = resolve_tool(_REACT_NATIVE_TOOL, repo_path)
    if binary is None:
        return RnBundleResult(
            status="unavailable",
            notes="react-native not found (node_modules + PATH miss)",
        )

    with ExitStack() as stack:
        td = stack.enter_context(scan_tempdir())
        build_env = dict(env) if env else build_scan_env(td)

        work = td / "repo"
        work.mkdir(parents=True, exist_ok=True)

        # CONTAINMENT (T-15-09): the output bundle MUST live OUTSIDE the read-only
        # target. The tempdir is guaranteed outside; assert it defensively.
        bundle_out = td / "index.android.bundle"
        if _is_under(bundle_out, repo_path):
            return RnBundleResult(
                status="unavailable",
                notes=(
                    "refusing to write the rn bundle under the scanned repo "
                    "(read-only contract); output must live outside the target tree"
                ),
            )

        # (2) Tracked-only copy: git archive → tarball → untar into work.
        src_tar = td / "src.tar"
        arch = run_tool(
            ["git", "-C", str(repo_path), "archive",
             "--format=tar", "-o", str(src_tar), "HEAD"],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if arch.returncode == TIMED_OUT:
            return RnBundleResult(status="timeout", notes="git archive timed out")
        if arch.returncode != 0:
            return RnBundleResult(
                status="unavailable",
                notes=(
                    "git archive failed (not a git repo, or no HEAD commit). "
                    f"stderr: {_tail(arch.stderr)}"
                ),
            )

        untar = run_tool(
            ["tar", "-xf", str(src_tar), "-C", str(work)],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if untar.returncode == TIMED_OUT:
            return RnBundleResult(status="timeout", notes="tar extract timed out")
        if untar.returncode != 0:
            return RnBundleResult(
                status="unavailable",
                notes=f"tar extract failed. stderr: {_tail(untar.stderr)}",
            )

        # (3) node_modules: Metro needs it; git archive omits it (gitignored).
        #     Hardlink-copy when present; otherwise note + proceed (the bundle
        #     step self-reports if it cannot resolve modules). We do NOT npm ci.
        nm_src = repo_path / "node_modules"
        nm_note = ""
        if nm_src.is_dir():
            cp = run_tool(
                ["cp", "-al", str(nm_src), str(work / "node_modules")],
                env=build_env,
                cwd=str(td),
                timeout_seconds=_COPY_TIMEOUT_SECONDS,
            )
            if cp.returncode != 0:
                nm_note = (
                    " (node_modules hardlink-copy failed — the bundle step may "
                    "self-report; `npm ci` is a future option)"
                )
        else:
            nm_note = (
                " (no node_modules in target — the bundle step would fail; "
                "`npm ci` is a future option)"
            )

        # (4) The build: react-native bundle --dev false (production size,
        #     MANDATORY) in the COPY; cwd=work, NEVER the target repo; output
        #     redirected to the tempdir.
        build = run_tool(
            [
                str(binary),
                "bundle",
                "--entry-file",
                config.rn_entry_file,
                "--platform",
                "android",
                "--dev",
                "false",
                "--bundle-output",
                str(bundle_out),
                "--assets-dest",
                str(td / "assets"),
            ],
            env=build_env,
            cwd=work,
            timeout_seconds=timeout_seconds,
        )
        if build.returncode == TIMED_OUT:
            return RnBundleResult(
                status="timeout", notes="react-native bundle timed out"
            )
        if build.returncode == EXEC_FAILED:
            return RnBundleResult(
                status="unavailable",
                notes="react-native could not be executed" + nm_note,
            )
        if build.returncode != 0:
            return RnBundleResult(
                status="unavailable",
                notes=(
                    f"react-native bundle failed (exit {build.returncode}). "
                    f"stderr: {_tail(build.stderr)}" + nm_note
                ),
            )

        # (5) Measure the produced bundle BEFORE the tempdir is destroyed.
        if not bundle_out.is_file():
            return RnBundleResult(
                status="unavailable",
                notes="bundle build succeeded but produced no bundle file" + nm_note,
            )
        size = bundle_out.stat().st_size
        findings = map_rn_bundle_bytes(
            size, config=config, prior_rn_bytes=prior_rn_bytes
        )
        return RnBundleResult(
            findings=findings,
            status="ok",
            notes=f"rn_bundle: diagnostic Metro build ({size} bytes)" + nm_note,
        )


__all__ = [
    "RnBundleResult",
    "RnBundleStatus",
    "collect_rn_bundle",
    "map_rn_bundle_bytes",
    "resolve_tool",
    "run_tool",
    "snapshot_git_status",
    "diff_git_status",
]
