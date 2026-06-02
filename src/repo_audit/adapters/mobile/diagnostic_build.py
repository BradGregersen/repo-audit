"""MOB-03 Tier-3b (9-T3b, double-gated ``--mobsf-build``) — diagnostic Gradle build.

The single riskiest operation in the whole tool: a real ``./gradlew assembleDebug``
build whose purpose is to produce a *debug* APK to feed Tier-3a MobSF when no
existing APK is present — WITHOUT ever mutating the read-only target tree.

PRIMARY SAFETY MECHANISM — the THROWAWAY COPY (09-RESEARCH § Architecture
Pattern 4). We copy the repo's *tracked* files into a tempdir, run the build
THERE, copy the resulting APK out, and discard the tempdir. The target tree is
NEVER the build cwd, so Gradle/AGP cannot dirty it. This is a hard structural
guarantee, not a hope: Gradle #25750 (OPEN) proves that NO combination of flags
redirects ALL Gradle/AGP output (``.gradle/``, ``local.properties``, ``.cxx/``
still leak into the project dir), so "redirect output in place" is rejected
outright — only a copy is safe.

BACKSTOP — the MOD-1 tripwire. We snapshot ``git status`` on the ORIGINAL tree
BEFORE any work and diff it AFTER the build. If the diff shows offenders, a copy
leaked somehow (a bug) and we self-report ``status="unavailable"`` with a MOD-1
note rather than hand back an APK from a run that dirtied the tree. Under normal
operation this tripwire NEVER fires — the copy already guarantees the contract;
the diff is a pure paranoia check on the real read-only invariant.

LOCKED DECISIONS:

  * ``assembleDebug`` ONLY. The argv NEVER names a release task or a bundle
    task — we never build a SHIPPING artifact (T-09-11; a structural grep test
    asserts no release/bundle gradle target is present anywhere in this module).
  * ALL Gradle caches live in the tempdir: ``GRADLE_USER_HOME`` +
    ``--project-cache-dir`` both point inside ``td``; ``--no-daemon`` prevents a
    lingering daemon from holding a lock or writing outside the tempdir (T-09-05).
  * Explicit 900 s timeout → ``run_tool`` SIGTERM→5s→SIGKILL; ``status="timeout"``,
    never hangs (T-09-06).
  * Every subprocess (git archive / tar / cp / gradlew) goes through the ONE
    ``run_tool`` seam (shell=False, list[str] argv) — no ``import subprocess``
    here, no shell-string injection via a crafted repo path (T-09-12).

``snapshot_git_status`` / ``diff_git_status`` are imported as MODULE-LEVEL names
so a test can monkeypatch ``diagnostic_build.snapshot_git_status`` to exercise the
MOD-1 tripwire host-independently (no real gradle, no real git state).

Registration (``@register_adapter("mobile")``) is Plan 05's; this module exports
only the build function + its result dataclass.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status

__all__ = ["build_debug_apk_copy", "build_apk", "BuildResult"]

# Wall-clock bound for the whole gradle invocation. A cold Android build with no
# warm cache can take minutes; 900 s is generous enough for a real first build
# yet still bounds a hang (T-09-06). git archive / tar / cp get short bounds.
_BUILD_TIMEOUT_SECONDS: float = 900.0
_ARCHIVE_TIMEOUT_SECONDS: float = 120.0
_COPY_TIMEOUT_SECONDS: float = 300.0

# How many chars of a failing tool's stderr we surface in the notes (bounded so a
# verbose gradle stacktrace doesn't balloon the result).
_STDERR_TAIL_CHARS: int = 600

BuildStatus = Literal["ok", "unavailable", "timeout"]


@dataclass
class BuildResult:
    """Outcome of a diagnostic debug-APK build.

    Attributes:
        apk_path: the STABLE path the built ``*-debug.apk`` was copied to
            (the caller-supplied ``out_apk``), or ``None`` when no APK was
            produced or the tripwire fired.
        status: ``"ok"`` (apk produced, tree clean), ``"unavailable"`` (no
            gradlew / no git / build failed / tripwire fired), or ``"timeout"``.
        notes: a human-readable reason (always set on a non-``ok`` result).
    """

    apk_path: Path | None
    status: BuildStatus
    notes: str


def _tail(text: str) -> str:
    """Return the last ``_STDERR_TAIL_CHARS`` chars of ``text`` (bounded)."""
    text = (text or "").strip()
    if len(text) <= _STDERR_TAIL_CHARS:
        return text
    return "…" + text[-_STDERR_TAIL_CHARS:]


def build_debug_apk_copy(
    target_repo: Path,
    *,
    env: dict[str, str] | None = None,
    timeout_seconds: float = _BUILD_TIMEOUT_SECONDS,
    out_apk: Path | None = None,
) -> BuildResult:
    """Build a debug APK from a THROWAWAY COPY of ``target_repo``; never in-place.

    The target tree is copied (tracked files only, via ``git archive``) into a
    tempdir, ``./gradlew assembleDebug`` runs THERE with every cache forced into
    the tempdir, and the resulting ``*-debug.apk`` is copied to ``out_apk`` (a
    STABLE path the caller owns) before the tempdir is destroyed. The original
    tree is never the build cwd — a structural read-only guarantee.

    Args:
        target_repo: the repo to build (read-only; never the build cwd).
        env: an optional pre-built env dict (e.g. a cache-redirected env). When
            absent, ``build_scan_env(td)`` supplies one. ``GRADLE_USER_HOME`` is
            forced into the tempdir on top of whichever env is used.
        timeout_seconds: wall-clock bound on the gradle invocation.
        out_apk: a STABLE path (owned by the caller, e.g. inside Plan 05's own
            ``scan_tempdir``) to copy the built APK to. The build tempdir here is
            destroyed on context exit, so the APK MUST be copied out before then.
            When ``None``, no APK can survive the call → the result is
            ``unavailable`` even on a successful build (with a note), because
            handing back a path inside a deleted tempdir would be a lie.

    Returns:
        A :class:`BuildResult`. NEVER raises — every failure mode (no git, no
        gradlew, build failure, timeout, tripwire) is folded into the result.
    """
    # (1) Backstop baseline on the ORIGINAL tree, taken BEFORE any work so the
    #     post-build diff measures only what (if anything) this call touched.
    pre = snapshot_git_status(target_repo)

    try:
        result = _build_in_tempdir(
            target_repo,
            env=env,
            timeout_seconds=timeout_seconds,
            out_apk=out_apk,
        )
    except Exception as exc:  # never-raise backstop
        result = BuildResult(
            apk_path=None,
            status="unavailable",
            notes=f"diagnostic build raised unexpectedly: {type(exc).__name__}: {exc}",
        )

    # (2) MOD-1 backstop: re-snapshot the ORIGINAL tree and diff. If the build
    #     leaked anything outside docs/state-reports/ a copy escaped (a bug) —
    #     self-report unavailable and NEVER return an APK from a dirtying run.
    offenders = diff_git_status(pre, snapshot_git_status(target_repo))
    if offenders:
        return BuildResult(
            apk_path=None,
            status="unavailable",
            notes=(
                "MOD-1 tripwire fired (diagnostic build leaked into the target "
                f"tree): {offenders}"
            ),
        )

    return result


def _build_in_tempdir(
    target_repo: Path,
    *,
    env: dict[str, str] | None,
    timeout_seconds: float,
    out_apk: Path | None,
) -> BuildResult:
    """The throwaway-copy build body (no tripwire — the caller owns that)."""
    target_repo = Path(target_repo)

    with scan_tempdir() as td:
        # Build env: redirect every Gradle cache INTO the tempdir.
        build_env = dict(env) if env else build_scan_env(td)
        build_env["GRADLE_USER_HOME"] = str(td / "gradle-home")

        work = td / "repo"
        work.mkdir(parents=True, exist_ok=True)

        # (3) Tracked-only copy: `git archive` to a tarball, then untar into work.
        #     git archive writes a clean snapshot of HEAD — no .git, no gitignored
        #     build output, no working-tree cruft. (For a non-git target a
        #     `cp -a` fallback would be needed; not implemented here — a non-git
        #     Android repo is out of scope for this plan and self-reports below.)
        src_tar = td / "src.tar"
        arch = run_tool(
            ["git", "-C", str(target_repo), "archive",
             "--format=tar", "-o", str(src_tar), "HEAD"],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if arch.returncode == TIMED_OUT:
            return BuildResult(None, "timeout", "git archive timed out")
        if arch.returncode != 0:
            return BuildResult(
                None,
                "unavailable",
                "git archive failed (not a git repo, or no HEAD commit); "
                "a non-git target would need a cp -a fallback (out of scope). "
                f"stderr: {_tail(arch.stderr)}",
            )

        untar = run_tool(
            ["tar", "-xf", str(src_tar), "-C", str(work)],
            env=build_env,
            cwd=str(td),
            timeout_seconds=_ARCHIVE_TIMEOUT_SECONDS,
        )
        if untar.returncode == TIMED_OUT:
            return BuildResult(None, "timeout", "tar extract timed out")
        if untar.returncode != 0:
            return BuildResult(
                None,
                "unavailable",
                f"tar extract failed. stderr: {_tail(untar.stderr)}",
            )

        # (4) RN node_modules (Pitfall 5): assembleDebug runs a Metro JS-bundle
        #     step that needs node_modules, which git archive omits (gitignored).
        #     Hardlink-copy it when present (cheap, no duplication). If the FS
        #     rejects hardlinks or node_modules is absent, record a note and
        #     proceed — the build may then self-report on the bundle step
        #     (honest). We deliberately do NOT run `npm ci` (network + slow) in
        #     this plan; a future option is documented in this note.
        nm_src = target_repo / "node_modules"
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
                    " (node_modules hardlink-copy failed — the JS-bundle step "
                    "may self-report; `npm ci` is a future option)"
                )
        else:
            nm_note = (
                " (no node_modules in target — a JS-bundle step would fail; "
                "`npm ci` is a future option)"
            )

        # (5) The build: assembleDebug ONLY — never a release task, never a
        #     bundle task. All caches in the tempdir; --no-daemon; cwd is the
        #     COPY, never the target repo.
        build = run_tool(
            [
                "./gradlew",
                "assembleDebug",
                "--no-daemon",
                f"--project-cache-dir={td / 'gradle-cache'}",
                "--gradle-user-home",
                str(td / "gradle-home"),
            ],
            env=build_env,
            cwd=work,
            timeout_seconds=timeout_seconds,
        )
        if build.returncode == TIMED_OUT:
            return BuildResult(None, "timeout", "gradle assembleDebug timed out")
        if build.returncode == EXEC_FAILED:
            return BuildResult(
                None,
                "unavailable",
                "no ./gradlew wrapper in the target repo (cannot diagnostic-build)"
                + nm_note,
            )
        if build.returncode != 0:
            return BuildResult(
                None,
                "unavailable",
                f"gradle assembleDebug failed (exit {build.returncode}). "
                f"stderr: {_tail(build.stderr)}" + nm_note,
            )

        # (6) Locate + extract the APK BEFORE the tempdir is destroyed.
        apk = next(work.rglob("*-debug.apk"), None)
        if apk is None:
            return BuildResult(
                None,
                "unavailable",
                "assembleDebug succeeded but no *-debug.apk was found" + nm_note,
            )
        if out_apk is None:
            return BuildResult(
                None,
                "unavailable",
                "built a *-debug.apk but no out_apk path was supplied; the build "
                "tempdir is destroyed on exit so the APK cannot survive "
                "(caller must pass out_apk inside its own scan_tempdir)" + nm_note,
            )

        out_apk = Path(out_apk)
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(apk, out_apk)  # local copy only — every other op via run_tool
        return BuildResult(out_apk, "ok", "assembleDebug build ok" + nm_note)


# Test-facing alias: the Wave-0 contract test (test_diagnostic_build.py) probes
# for ``diagnostic_build`` / ``run_diagnostic_build`` / ``build_apk`` and calls it
# with a single positional ``repo``. ``build_debug_apk_copy`` already accepts that
# (out_apk defaults to None for the unit path), so this alias satisfies the test
# without forking the implementation.
build_apk = build_debug_apk_copy
