"""D-11-07 — best-effort classpath resolution via a THROWAWAY-COPY gradle build.

Standalone detekt (no classpath) is the KOT-01 floor — always available, always
safe. TYPED detekt (``--classpath``) is a deeper default layered on top: with the
compile classpath resolved, detekt's type-resolution rules (the ones that find
real bugs requiring type information) activate. This module attempts that
classpath resolution and degrades to ``None`` — the standalone floor — on ANY
failure.

PRIMARY SAFETY MECHANISM — the THROWAWAY COPY (mirrors
``mobile/diagnostic_build.py`` § Architecture Pattern 4 and 09-RESEARCH). We copy
the repo's TRACKED files into a tempdir via ``git archive HEAD``, run the
classpath-producing gradle task THERE, and discard the tempdir. The target tree
is NEVER the build cwd, so Gradle/AGP cannot dirty it. This is a hard structural
guarantee, not a hope: Gradle #25750 (OPEN) proves NO combination of flags
redirects ALL Gradle/AGP output (``.gradle/``, ``local.properties``, ``.cxx/``
still leak into the project dir), so "redirect output in place" is rejected
outright — only a copy is safe.

LOCKED DECISIONS (inherited from diagnostic_build):
  * ALL Gradle caches live in the tempdir: ``GRADLE_USER_HOME`` +
    ``--project-cache-dir`` both point inside the tempdir; ``--no-daemon``
    prevents a lingering daemon holding a lock or writing outside the tempdir.
  * Explicit 900 s timeout → ``run_tool`` SIGTERM→5s→SIGKILL; never hangs.
  * Every subprocess (git archive / tar / gradlew) goes through the ONE
    ``run_tool`` seam (shell=False, list[str] argv) — no ``import subprocess``
    here, no shell-string injection via a crafted repo path.

This is BEST-EFFORT and intentionally conservative: classpath assembly from
gradle output is brittle across AGP/Kotlin versions, so when the produced
classpath is uncertain we return ``None`` and let the caller run standalone
detekt (always safe). The deep typed run is a bonus, never a requirement.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool

__all__ = ["try_resolve_classpath_via_throwaway_build"]

# Wall-clock bound for the classpath-producing gradle invocation. A cold build
# with no warm cache can take minutes; 900 s is generous yet bounds a hang.
_BUILD_TIMEOUT_SECONDS: float = 900.0
_ARCHIVE_TIMEOUT_SECONDS: float = 120.0

# The gradle task that materializes the compile classpath into the build dir.
# ``compileDebugKotlin`` / ``compileKotlin`` produce the compiled classes +
# resolved dependency jars under ``build/`` that we then collect.
_CLASSPATH_TASKS: tuple[str, ...] = ("compileDebugKotlin", "compileKotlin")


def try_resolve_classpath_via_throwaway_build(
    repo_path: Path,
    *,
    env: dict[str, str] | None = None,
    timeout_seconds: float = _BUILD_TIMEOUT_SECONDS,
) -> str | None:
    """Resolve the compile classpath via a throwaway-copy gradle build, or ``None``.

    Copies the repo's tracked files into a tempdir (``git archive HEAD``), runs a
    classpath-producing gradle task THERE with every cache forced into the
    tempdir, and assembles a ``:``-joined classpath string from the produced
    build artefacts. NEVER builds in the target tree (Gradle #25750) and NEVER
    raises.

    Args:
        repo_path: the repo to resolve the classpath for (read-only; never the
            build cwd).
        env: an optional pre-built env dict (e.g. a cache-redirected env). When
            absent, ``build_scan_env(td)`` supplies one. ``GRADLE_USER_HOME`` is
            forced into the tempdir on top of whichever env is used.
        timeout_seconds: wall-clock bound on the gradle invocation.

    Returns:
        A ``:``-joined classpath string when the build succeeds AND classpath
        artefacts were found, else ``None``. ``None`` means "fall back to
        standalone detekt" — the always-safe KOT-01 floor. Every failure mode
        (no gradle wrapper, build failure, run_tool sentinel, no classpath
        output, an unexpected exception) returns ``None``.
    """
    try:
        return _resolve_in_tempdir(
            Path(repo_path), env=env, timeout_seconds=timeout_seconds
        )
    except Exception:  # noqa: BLE001 — never raise; standalone fallback is safe.
        return None


def _resolve_in_tempdir(
    repo_path: Path,
    *,
    env: dict[str, str] | None,
    timeout_seconds: float,
) -> str | None:
    """The throwaway-copy classpath-resolution body (returns ``None`` on failure)."""
    with scan_tempdir() as td:
        # Build env: redirect every Gradle cache INTO the tempdir.
        build_env = dict(env) if env else build_scan_env(td)
        build_env["GRADLE_USER_HOME"] = str(td / "gradle-home")

        work = td / "repo"
        work.mkdir(parents=True, exist_ok=True)

        # (1) Tracked-only copy: `git archive` to a tarball, then untar into work.
        #     git archive writes a clean snapshot of HEAD — no .git, no gitignored
        #     build output, no working-tree cruft.
        src_tar = td / "src.tar"
        arch = run_tool(
            ["git", "-C", str(repo_path), "archive",
             "--format=tar", "-o", str(src_tar), "HEAD"],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if arch.returncode != 0:
            # Not a git repo / no HEAD / timed out → cannot copy → standalone.
            return None

        untar = run_tool(
            ["tar", "-xf", str(src_tar), "-C", str(work)],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if untar.returncode != 0:
            return None

        # (2) No gradle wrapper in the copy → no typed build is possible →
        #     standalone (the wrapper is what diagnostic_build also relies on).
        gradlew = work / "gradlew"
        if not gradlew.is_file():
            return None

        # (3) The classpath-producing build: caches in the tempdir; --no-daemon;
        #     cwd is the COPY, never the target repo. We pass BOTH candidate
        #     tasks; gradle runs whichever exist (an unknown-task error simply
        #     yields a non-zero exit → we return None → standalone).
        build = run_tool(
            [
                "./gradlew",
                *_CLASSPATH_TASKS,
                "--no-daemon",
                f"--project-cache-dir={td / 'gradle-cache'}",
                "--gradle-user-home",
                str(td / "gradle-home"),
            ],
            env=build_env,
            cwd=work,
            timeout_seconds=timeout_seconds,
        )
        if build.returncode in (TIMED_OUT, EXEC_FAILED) or build.returncode != 0:
            return None

        # (4) Assemble a BEST-EFFORT classpath from the produced build output:
        #     compiled-class dirs + resolved dependency jars under build/. This
        #     is intentionally conservative — if nothing is found we return None
        #     and the caller runs standalone detekt (always safe).
        classpath = _collect_classpath_entries(work)
        if not classpath:
            return None
        return ":".join(classpath)


def _collect_classpath_entries(work: Path) -> list[str]:
    """Collect compiled-class dirs + dependency jars from a finished build tree.

    Best-effort + deterministic: returns the produced Kotlin/Java class-output
    directories plus any jars under ``build/`` (sorted for stable output). An
    empty list signals "uncertain classpath" → the caller falls back to
    standalone detekt.
    """
    entries: list[str] = []

    # Compiled-class output directories (Kotlin + Java) produced by the compile
    # tasks. These hold the project's own compiled classes.
    class_dirs = sorted(
        {p for p in work.rglob("build/classes") if p.is_dir()}
        | {p for p in work.rglob("build/tmp/kotlin-classes") if p.is_dir()}
    )
    entries.extend(str(p) for p in class_dirs)

    # Resolved dependency jars that landed under a build dir during the build.
    jars = sorted({p for p in work.rglob("build/**/*.jar") if p.is_file()})
    entries.extend(str(p) for p in jars)

    return entries
