"""D-41' opt-in coverage refresh — test-runner subprocess invocation.

Public API:
    * ``refresh_coverage(repo_root, cfg, env) -> RefreshResult`` — invoke the
      resolved runner in-place, never raises.
    * ``resolve_runner_command(repo_root, *, stack, override) -> list[str] | None``
      — D-11-09 per-stack runner resolution (zero-config default + light
      manifest probe + override). Callers pass the resolved command into
      ``refresh_coverage`` via ``cfg["command"]``; a ``None`` return means no
      confident runner was found and the caller marks the coverage tier
      ``unavailable`` (never guess-and-run — T-11-03-05).

D-11-09 (TST-01): coverage is produced by ACTUALLY running the test suite
(jest/vitest ``--coverage``, ``pytest --cov --cov-report=lcov:coverage/lcov.info``,
``./gradlew koverXmlReport``) in-place under the refresh flag — not import-only.
pytest-cov + jest sink into the EXISTING ``parsers/lcov.py`` aggregate Finding
via the ``coverage/lcov.info`` artifact (11-RESEARCH Pitfall 8: the ``:DEST``
form is mandatory — bare ``--cov-report=lcov`` writes ``coverage.lcov`` in CWD,
which the lcov parser does NOT read). kover instead emits JaCoCo-XML at
``build/reports/kover/report.xml`` (11-RESEARCH Pitfall 9), parsed by
``parsers/kover_xml.parse_kover_xml`` — NOT lcov. Therefore
``RefreshResult.lcov_produced`` is the lcov-path signal ONLY; for kover the
caller (Plan 05) checks the JaCoCo artifact via ``parse_kover_xml`` rather than
``lcov_produced``. ``refresh_coverage``'s in-place exec / ``_scrub_secrets`` /
``_redact_tail`` / timeout / ``RefreshResult`` machinery is reused UNCHANGED;
this module only adds the resolver — it does NOT alter the runner subprocess
path or the ``lcov_produced`` check.

SCOPE: refresh.py is the orchestration primitive only. It does NOT
construct any Finding object. The runner-failure Finding shape lives in
plan 03-03's ``_refresh_failed_finding(refresh_result, runner_command)``
helper, which plan 03-05's CLI failure-synthesis path calls. This
separation keeps the Finding schema import boundary in the parsers
module where the schema imports already live.

Layered defenses (T-03-refresh-*):
    * subprocess.run with shell=False, list[str] argv (T-03-refresh-injection)
    * Explicit timeout from cfg['timeout_ms'] (T-03-refresh-dos)
    * Env scrub of secret-shaped variables (T-03-refresh-env-leak)
    * C13 redaction on stderr tail (T-03-refresh-secret-disclosure)
    * Both stdout_tail AND stderr_tail bounded to ≤2 KB (M2 bound output)

Accepted (documented, NOT mitigated in Phase 3):
    * T-03-refresh-supplychain: target-repo's package.json ``test`` script
      may execute arbitrary code (e.g. postinstall hooks if running after
      ``npm install``). Users opting into refresh accept this; the tool's
      threat model assumes the user runs against repos they trust.
    * T-03-refresh-egress: network egress during the test run is permitted;
      Phase 7+ may add firejail/bwrap sandboxing.

Forbidden-literal discipline (mirrors plan 03-03's pattern): this module
intentionally does NOT pull in the parsers' schema module nor reference
the parsers' Finding constructor by name. Those literals are absent from
the source on purpose; ``test_refresh_does_not_import_finding`` greps the
module source to pin the separation.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RefreshStatus = Literal["ok", "failed", "timeout", "skipped"]


class RefreshResult(BaseModel):
    """Outcome of ``refresh_coverage()`` — surfaced into ScopeLedger by cli.py.

    Bounds (M2 / T-03-refresh-dos):
        * ``stdout_tail`` and ``stderr_tail`` are each ≤2048 bytes (2 KB).
        * Truncation happens at construction via ``_redact_tail``; downstream
          consumers (plan 03-03's ``_refresh_failed_finding``) do NOT
          re-truncate.

    No Finding construction here — refresh.py is the orchestration primitive.
    Plan 03-03 owns the Finding schema boundary via ``_refresh_failed_finding``.
    """

    model_config = ConfigDict(extra="forbid")
    status: RefreshStatus
    runner_command: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    stdout_tail: str = ""        # ≤ 2 KB; capped by _redact_tail
    stderr_tail: str = ""        # ≤ 2 KB; capped by _redact_tail + C13 redacted
    lcov_produced: bool = False
    notes: str = ""
    exit_code: int | None = None  # subprocess returncode when known; None on timeout/OSError


# ---------------------------------------------------------------------------
# Module-level constants

_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
)

# M2 / T-03-refresh-dos: bound both tail buffers to 2 KB at construction.
# Plan 03-03's ``_refresh_failed_finding`` relies on this bound and does NOT
# re-truncate. Keep this constant the single source of truth.
_TAIL_CAP: int = 2048

_LCOV_REL: str = "coverage/lcov.info"


# ---------------------------------------------------------------------------
# Private helpers


def _scrub_secrets(env: dict[str, str]) -> dict[str, str]:
    """Strip env vars whose name suffix-matches a secret-shaped pattern.

    Conservative: any ``*_TOKEN``, ``*_KEY``, ``*_SECRET``, ``*_PASSWORD``,
    ``*_PASSWD`` goes. False-positive stripping (e.g. ``PUBLIC_KEY``) is
    acceptable; false-negative (leaking a real secret) is not. Returns a
    NEW dict — does not mutate the input.
    """
    return {
        k: v
        for k, v in env.items()
        if not any(k.upper().endswith(sfx) for sfx in _SECRET_KEY_SUFFIXES)
    }


def _redact_tail(text: str) -> str:
    """Truncate to ``_TAIL_CAP`` and apply C13 redaction.

    The renderer chokepoint (Phase 1 D-07) remains the final structural
    guard; this is defensive-in-depth at the subprocess boundary. When the
    secret_lint primitive raises, that signal is escalated — the rendered
    report would be refused at write-time anyway, so a hit at the refresh
    boundary becomes a redacted notice rather than a crash.
    """
    snippet = text[-_TAIL_CAP:] if len(text) > _TAIL_CAP else text
    try:
        from repo_audit.render.secret_lint import lint_buffer, SecretsDetected

        try:
            lint_buffer(snippet, buffer_name="refresh_stderr")
        except SecretsDetected as hits:
            return (
                f"[REDACTED: {len(snippet)} chars contained "
                f"{len(hits.hits)} potential secrets]"
            )
    except Exception:  # pragma: no cover — defensive
        pass
    return snippet


# ---------------------------------------------------------------------------
# D-11-09 per-stack runner resolution

# Per-stack zero-config defaults (D-11-09). These are OUR constants, never
# derived from untrusted repo strings (T-11-03-05). The probe below only
# DISAMBIGUATES which default to pick (or returns None); it never synthesises a
# command from file contents.
_PYTEST_LCOV_DEST: str = "coverage/lcov.info"  # Pitfall 8 :DEST form (matches LCOV_RELATIVE_PATH)
_PYTEST_DEFAULT: list[str] = [
    "pytest",
    "--cov",
    f"--cov-report=lcov:{_PYTEST_LCOV_DEST}",
]
_KOVER_DEFAULT: list[str] = ["./gradlew", "koverXmlReport"]

_NODE_STACKS: frozenset[str] = frozenset(
    {"typescript-node", "expo", "react-native"}
)


def resolve_runner_command(
    repo_root: Path,
    *,
    stack: str,
    override: dict | None = None,
) -> list[str] | None:
    """D-11-09: resolve the per-stack coverage runner command.

    Zero-config default + light manifest probe + override. Returns the argv the
    caller passes into ``refresh_coverage`` via ``cfg["command"]``, or ``None``
    when no confident runner can be resolved — in which case the caller marks
    the coverage tier ``unavailable`` (NEVER guess-and-run — T-11-03-05). The
    returned argv is always OUR constants or the user's explicit override, never
    derived from untrusted repo strings.

    On a successful run the resulting artifact is stack-specific:
        * python / node → ``coverage/lcov.info`` (read by ``parsers/lcov.py``)
        * kotlin        → ``build/reports/kover/report.xml`` (read by
          ``parsers/kover_xml.parse_kover_xml``, NOT lcov)
    The caller checks the appropriate artifact for the resolved stack.

    Args:
        repo_root: target repo root (the manifest probe reads under this).
        stack: the detected stack literal (e.g. ``"python"``, ``"typescript-node"``,
            ``"expo"``, ``"react-native"``, ``"kotlin-android"``).
        override: the ``.repo-audit.yaml`` ``coverage_refresh`` block, if
            present. ``override["command"]`` (a non-empty list) WINS over every
            default/probe (D-11-09 user override).

    Returns:
        The resolved argv as ``list[str]``, or ``None`` when nothing resolves
        confidently.
    """
    repo = Path(repo_root)

    # Override wins (D-11-09). The user's explicit command is authoritative.
    if override:
        cmd = override.get("command")
        if cmd:
            return [str(part) for part in cmd]

    if stack == "python":
        return _resolve_python(repo)
    if stack in _NODE_STACKS:
        return _resolve_node(repo)
    if stack == "kotlin-android":
        return _resolve_kotlin(repo)
    return None


def _resolve_python(repo: Path) -> list[str] | None:
    """Python: pytest-cov with the Pitfall-8 :DEST lcov form.

    Default ``["pytest", "--cov", "--cov-report=lcov:coverage/lcov.info"]`` — the
    ``:DEST`` form lands the artifact at the path the lcov parser reads, and the
    bare ``--cov`` covers the repo when no package is specified. If poetry is
    indicated (``poetry.lock`` present), prefix ``["poetry", "run", ...]``. If no
    pytest config and no ``tests`` dir is detected confidently → ``None``.
    """
    has_pytest_cfg = (
        (repo / "pytest.ini").is_file()
        or (repo / "tox.ini").is_file()
        or _pyproject_mentions(repo, "pytest")
        or (repo / "setup.cfg").is_file()
    )
    has_tests_dir = (repo / "tests").is_dir() or (repo / "test").is_dir()
    if not (has_pytest_cfg or has_tests_dir):
        return None  # no confident pytest target — never guess-and-run

    cmd = list(_PYTEST_DEFAULT)
    if (repo / "poetry.lock").is_file():
        return ["poetry", "run", *cmd]
    return cmd


def _resolve_node(repo: Path) -> list[str] | None:
    """Node stacks (TS / Expo / RN): probe package.json scripts, never invent one.

    If a ``coverage`` script exists → ``["npm", "run", "coverage"]``; elif a
    ``test`` script exists → ``["npm", "test", "--", "--coverage"]``. The
    vitest-vs-jest devDependency presence only picks the default flag for an
    EXISTING ``test`` script (``--coverage`` is the same flag for both runners);
    it NEVER invents a missing script. No usable script → ``None``.
    """
    pkg = repo / "package.json"
    if not pkg.is_file():
        return None
    try:
        import json

        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return None
    if scripts.get("coverage"):
        return ["npm", "run", "coverage"]
    if scripts.get("test"):
        # --coverage is recognised by both jest and vitest; devDependency
        # presence (jest/vitest) only confirms a coverage-capable runner backs
        # the existing test script, never to synthesise a missing one.
        return ["npm", "test", "--", "--coverage"]
    return None


def _resolve_kotlin(repo: Path) -> list[str] | None:
    """Kotlin: only return koverXmlReport if a kover plugin / task is present.

    Probe ``build.gradle.kts`` / ``build.gradle`` for a ``kover`` plugin
    reference or the ``koverXmlReport`` task (RESEARCH Open Q3). Present →
    ``["./gradlew", "koverXmlReport"]``. Absent → ``None`` (never invent the
    gradle task — T-11-03-05).
    """
    for name in ("build.gradle.kts", "build.gradle"):
        gradle = repo / name
        if not gradle.is_file():
            continue
        try:
            text = gradle.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "kover" in text or "koverXmlReport" in text:
            return list(_KOVER_DEFAULT)
    return None


def _pyproject_mentions(repo: Path, needle: str) -> bool:
    """True if pyproject.toml exists and textually mentions ``needle``.

    A lightweight presence probe (NOT a command extraction): used only to decide
    WHETHER to apply OUR default pytest command, never to build one from the
    file's contents.
    """
    pyproject = repo / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        return needle in pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Public entry point


def refresh_coverage(
    repo_root: Path,
    cfg: dict,
    env: dict[str, str],
) -> RefreshResult:
    """Invoke the target-repo's test runner to produce ``coverage/lcov.info``.

    Never raises across the function boundary. Returns ONLY ``RefreshResult``
    (data) — does NOT construct any Finding. The Finding-shape boundary is
    plan 03-03's ``_refresh_failed_finding(refresh_result, runner_command)``.
    See module docstring for threat-model dispositions.

    Args:
        repo_root: target repo root (cwd for the subprocess).
        cfg: dict from adapter.yaml ``tools.coverage_refresh`` block, e.g.
            ``{'mode': 'auto', 'command': ['npm', 'test'], 'timeout_ms': 600000}``.
            Caller ensures ``mode != 'off'`` before calling (this function
            does NOT re-check mode).
        env: env dict from ``build_scan_env()``; ``refresh_coverage`` applies
            an ADDITIONAL secret-shaped-key scrub on top.

    Returns:
        ``RefreshResult``; never raises across the function boundary.
    """
    argv = list(cfg.get("command") or ["npm", "test"])
    timeout_s = float(cfg.get("timeout_ms", 600_000)) / 1000.0
    scrubbed_env = _scrub_secrets(env)
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(
            argv,
            cwd=str(repo_root),
            env=scrubbed_env,
            shell=False,                # CLAUDE.md / M2/M6 hard rule
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        raw_stderr = e.stderr
        if isinstance(raw_stderr, bytes):
            stderr_text = raw_stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = raw_stderr or ""
        return RefreshResult(
            status="timeout",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail="",
            stderr_tail=_redact_tail(stderr_text),
            lcov_produced=False,
            notes=f"timeout after {timeout_s:.1f}s",
            exit_code=None,
        )
    except (FileNotFoundError, OSError) as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return RefreshResult(
            status="failed",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail="",
            stderr_tail="",
            lcov_produced=False,
            notes=f"coverage_refresh_failed: {type(e).__name__}: {e}",
            exit_code=None,
        )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    lcov_produced = (repo_root / _LCOV_REL).is_file()
    stdout_tail = _redact_tail(cp.stdout or "")
    stderr_tail = _redact_tail(cp.stderr or "")

    if cp.returncode == 0 and lcov_produced:
        return RefreshResult(
            status="ok",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
            lcov_produced=True,
            notes="coverage refreshed",
            exit_code=0,
        )

    if cp.returncode != 0:
        return RefreshResult(
            status="failed",
            runner_command=argv,
            duration_ms=elapsed_ms,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
            lcov_produced=lcov_produced,
            notes=(
                f"coverage_refresh_failed: runner exit {cp.returncode}; "
                f"{stderr_tail[:200]}"
            ),
            exit_code=cp.returncode,
        )

    # returncode 0 but no lcov produced — test script didn't generate coverage.
    return RefreshResult(
        status="failed",
        runner_command=argv,
        duration_ms=elapsed_ms,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        lcov_produced=False,
        notes=(
            "coverage_refresh_failed: runner exited 0 but coverage/lcov.info "
            "not produced"
        ),
        exit_code=cp.returncode,
    )


__all__ = [
    "RefreshResult",
    "RefreshStatus",
    "refresh_coverage",
    "resolve_runner_command",
]
