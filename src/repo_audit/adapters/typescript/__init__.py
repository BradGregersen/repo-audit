"""TypeScript / Node stack adapter (D-37 + D-38 + D-39 + D-40 + D-45/46).

Module-load contract:
    1. Load ``adapter.yaml`` (same directory) via ruamel.yaml's safe
       loader — T-03-01 structural mitigation against deserialisation
       attacks in a future user-overlay scenario.
    2. Expose the loaded config as ``ADAPTER_CONFIG`` (the canonical
       name used by tests and downstream consumers) AND as the alias
       ``CONFIG`` (the name the plan spec uses).
    3. Apply ``@register_adapter("typescript-node")`` to ``run``, so
       importing this package fires registration exactly once.

Wave-1 invariants:
    * Importing this module triggers a SINGLE @register_adapter call;
      double imports are idempotent only because Python's module-cache
      means the registration code runs once.
    * The adapter ``run()`` produces exactly four ``AdapterResult``
      records on a TypeScript-node stack: one per
      ``required_collectors`` entry (tsc, eslint, knip, coverage_lcov).
    * When ANY of the four tools is unavailable (binary missing,
      parser module not yet shipped, subprocess timeout, etc.) the
      adapter emits ``AdapterResult(status='unavailable', notes=<why>)``
      rather than raising. The scope ledger surfaces the row.
    * Subprocess invocations always use ``shell=False``,
      ``list[str]`` argv, explicit ``timeout`` and the D-46
      cache-redirected env. T-03-02 + T-03-04 structural mitigations.

Wave-2 will replace the parser stubs with real implementations under
``./parsers/{tsc,eslint,knip,lcov}.py``. The dispatch path
(``_load_parser`` → ``parser_callable(InvocationResult)``) is in
place now; the parser modules being absent simply means each tool
falls through to ``status='unavailable'`` until Wave 2 lands.
"""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from repo_audit.adapters.base import AdapterResult, InvocationResult
from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.registry import register_adapter
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, run_tool
from repo_audit.adapters.typescript.detection import detect_eslint_config
from repo_audit.schema.detection import DetectionResult


# --- adapter.yaml load (T-03-01 safe-mode) --------------------------------

_ADAPTER_YAML_PATH = Path(__file__).parent / "adapter.yaml"


def _load_adapter_yaml() -> dict[str, Any]:
    """Load ``adapter.yaml`` under ruamel.yaml's safe loader.

    T-03-01: ``YAML(typ='safe')`` refuses ``!!python/object`` and
    ``!!python/name`` constructors. Future user-overlay merge logic
    (Phase 7) MUST start from this same loader posture.

    A separate function (rather than inlining at module scope) makes
    the loader posture greppable for the structural test
    ``test_yaml_loaded_in_safe_mode``.
    """
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"adapter.yaml at {_ADAPTER_YAML_PATH} did not load as a mapping; "
            f"got {type(data).__name__}"
        )
    return data


# Public config dict. Both names point at the same object — ADAPTER_CONFIG
# is the canonical test-and-consumer name; CONFIG is the plan-spec alias.
ADAPTER_CONFIG: dict[str, Any] = _load_adapter_yaml()
CONFIG: dict[str, Any] = ADAPTER_CONFIG


# --- D-39 parser dispatch -------------------------------------------------

def _load_parser(dotted_path: str):
    """Import and return the parser callable at ``dotted_path``.

    Accepts BOTH dotted-attribute (``pkg.mod.func``) and colon-suffix
    (``pkg.mod:func``) styles — the latter is the entry-points
    convention and is the form ``adapter.yaml`` uses.

    Raises ``ModuleNotFoundError`` if the module is absent (Wave 1: this
    is the expected path for every parser until Wave 2 lands them).
    Raises ``AttributeError`` if the module exists but the function
    name is wrong.
    """
    if ":" in dotted_path:
        mod_name, func_name = dotted_path.rsplit(":", 1)
    else:
        mod_name, _, func_name = dotted_path.rpartition(".")
        if not mod_name:
            raise ValueError(
                f"parser path {dotted_path!r} has no module component"
            )
    module = importlib.import_module(mod_name)
    return getattr(module, func_name)


# --- subprocess invocation helper ----------------------------------------

def _invoke_subprocess(
    tool_bin: Path,
    extra_args: list[str],
    env: dict[str, str],
    timeout_seconds: float,
    cwd: Path,
) -> InvocationResult:
    """Run ``[tool_bin, *extra_args]`` under the supplied env.

    D-06-11: this now delegates to the single shared tool-ops wrapper
    (``adapters/toolops.run_tool``) so there is ONE subprocess invocation
    path across the whole codebase, not a per-adapter copy. The wrapper
    enforces the same structural mitigations this helper used to roll itself:

        * ``shell=False`` + ``list[str]`` argv (T-03-02 / T-06-01) — and now
          additionally a ``TypeError`` guard if a str argv ever slips in.
        * Explicit ``timeout`` with SIGTERM→5s→SIGKILL escalation (FND-04) —
          a stronger no-hang guarantee than the prior bare
          ``subprocess.run(timeout=…)``, which never gracefully escalated.
        * ``returncode == -2`` timeout sentinel (unchanged) — the caller
          (``_run_subprocess_tool``) flips it into ``status='timeout'``.
        * ``returncode == -1`` exec-failed sentinel — the wrapper folds a
          vanished/​un-exec'able binary into this instead of raising
          ``FileNotFoundError``; the caller maps it to ``status='unavailable'``
          (the same outcome the old ``except FileNotFoundError`` produced).
        * stdout/stderr decoded utf-8/replace; output bounded by the timeout
          (T-03-05 disposition: accept).
    """
    argv = [str(tool_bin), *extra_args]
    return run_tool(
        argv,
        env=env,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )


# --- per-tool result builders --------------------------------------------

def _make_unavailable(
    source_tool: str, dimension: str, notes: str
) -> AdapterResult:
    """Compose an AdapterResult with status='unavailable' for a missing tool."""
    return AdapterResult(
        status="unavailable",
        notes=notes,
        source_adapter="typescript-node",
        source_tool=source_tool,
        dimension=dimension,
    )


def _run_subprocess_tool(
    tool_name: str,
    tool_cfg: dict[str, Any],
    repo_path: Path,
    tempdir: Path,
    env: dict[str, str],
) -> AdapterResult:
    """Resolve, invoke, and parse a single subprocess-style tool.

    The full failure ladder (D-25 cross-boundary safety):
        1. ``resolve_tool`` returns None ⇒ unavailable.
        2. Subprocess raises FileNotFoundError ⇒ unavailable.
        3. Subprocess times out (returncode == -2) ⇒ timeout.
        4. Parser module absent (ModuleNotFoundError) ⇒ unavailable.
        5. Parser raises any other exception ⇒ unavailable + notes.
        6. Parser returns non-list ⇒ unavailable + notes.

    Wave 1: paths (4)–(6) are the expected outcome for every tool
    because the parser modules don't ship until Wave 2.
    """
    dimension = tool_cfg.get("dimension", "")
    timeout_ms = tool_cfg.get("timeout_ms", 60_000)
    timeout_seconds = float(timeout_ms) / 1000.0

    tool_bin = resolve_tool(tool_cfg["command"], repo_path)
    if tool_bin is None:
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} binary not found (node_modules/.bin walk-up + PATH exhausted)",
        )

    # Per-tool argv augmentation for cache-redirection (D-46).
    extra_args = list(tool_cfg.get("args", []))
    if tool_name == "eslint":
        extra_args.extend(["--cache-location", str(tempdir / ".eslintcache")])
    elif tool_name == "tsc":
        extra_args.extend(["--tsBuildInfoFile", str(tempdir / ".tsbuildinfo")])

    # _invoke_subprocess now delegates to the shared run_tool wrapper, which
    # NEVER raises — a vanished/un-exec'able binary comes back as the -1
    # exec-failed sentinel rather than a FileNotFoundError/OSError. The
    # try/except below is retained as defence-in-depth (a future direct caller
    # or a bug that re-raises) but the -1 mapping is the live path now.
    try:
        invocation = _invoke_subprocess(
            tool_bin,
            extra_args,
            env=env,
            timeout_seconds=timeout_seconds,
            cwd=repo_path,
        )
    except FileNotFoundError as exc:  # pragma: no cover — run_tool folds this into -1
        return _make_unavailable(
            tool_name, dimension, f"binary disappeared between resolve and invoke: {exc}"
        )
    except OSError as exc:  # pragma: no cover — run_tool folds this into -1
        return _make_unavailable(
            tool_name, dimension, f"subprocess OSError: {exc}"
        )

    if invocation.returncode == EXEC_FAILED:
        # -1: the shared wrapper could not exec the binary (vanished between
        # resolve and invoke, or permission denied). Same outcome the old
        # ``except FileNotFoundError`` produced — status='unavailable'.
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} binary could not be executed: {invocation.stderr}",
        )

    if invocation.returncode == -2:
        return AdapterResult(
            status="timeout",
            notes=f"{tool_name} exceeded timeout of {timeout_seconds:.1f}s",
            source_adapter="typescript-node",
            source_tool=tool_name,
            dimension=dimension,
        )

    parser_path = tool_cfg.get("parser") or tool_cfg.get("parser_dotted_path")
    if not parser_path:
        return _make_unavailable(
            tool_name, dimension, f"{tool_name}: no parser dotted path declared in adapter.yaml"
        )

    try:
        parse_fn = _load_parser(parser_path)
    except ModuleNotFoundError:
        # Wave 1 expected path — parser module ships in Wave 2.
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} parser module {parser_path!r} not yet implemented (Wave 2)",
        )
    except (AttributeError, ValueError, ImportError) as exc:
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} parser dispatch failed: {type(exc).__name__}: {exc}",
        )

    try:
        findings = parse_fn(invocation)
    except Exception as exc:  # noqa: BLE001 — D-25 boundary
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} parser raised {type(exc).__name__}: {exc}",
        )

    if not isinstance(findings, list):
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} parser returned {type(findings).__name__}, not list",
        )

    return AdapterResult(
        findings=findings,
        status="ok",
        source_adapter="typescript-node",
        source_tool=tool_name,
        dimension=dimension,
        duration_ms=invocation.duration_ms,
    )


def _run_file_reader_tool(
    tool_name: str, tool_cfg: dict[str, Any], repo_path: Path
) -> AdapterResult:
    """Handle ``command: null`` tools (the lcov file-reader path).

    Unlike subprocess tools, file-readers receive the repo_path
    directly. The parser decides how to surface missing/stale files
    (D-43, D-44) — typically as a single ``unavailable`` Finding.

    Wave 1: parser module absent ⇒ status='ok' with empty findings.
    The result still counts toward the four-records contract; the
    parser module's absence is benign here because the file-reader
    path doesn't itself fail when the parser is missing.
    """
    dimension = tool_cfg.get("dimension", "")
    parser_path = tool_cfg.get("parser") or tool_cfg.get("parser_dotted_path")

    if not parser_path:
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name}: no parser dotted path declared in adapter.yaml",
        )

    try:
        parse_fn = _load_parser(parser_path)
    except ModuleNotFoundError:
        # Wave 1 expected path — return an OK shell so the four-result
        # contract holds. Findings list is empty until Wave 2 lands the
        # parser. The notes field is left empty so the result reads as
        # "tool ran cleanly with no findings" rather than "unavailable",
        # matching the Wave-2 file-reader's behaviour on a clean fresh
        # lcov.info (no per-file findings, one aggregate Finding which
        # the Wave-2 parser produces).
        return AdapterResult(
            status="ok",
            source_adapter="typescript-node",
            source_tool=tool_name,
            dimension=dimension,
        )
    except (AttributeError, ValueError, ImportError) as exc:
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} parser dispatch failed: {type(exc).__name__}: {exc}",
        )

    try:
        findings = parse_fn(repo_path)
    except Exception as exc:  # noqa: BLE001 — D-25 boundary
        return _make_unavailable(
            tool_name,
            dimension,
            f"{tool_name} file-reader raised {type(exc).__name__}: {exc}",
        )

    if not isinstance(findings, list):
        # A single Finding is also acceptable from the file-reader
        # (the D-44 aggregate Finding). Wrap it.
        findings = [findings] if findings is not None else []

    return AdapterResult(
        findings=findings,
        status="ok",
        source_adapter="typescript-node",
        source_tool=tool_name,
        dimension=dimension,
    )


# --- public entry point ---------------------------------------------------

@register_adapter("typescript-node")
def run(repo_path: Path, detection: DetectionResult) -> list[AdapterResult]:
    """TypeScript adapter entry point.

    Iterates ADAPTER_CONFIG['required_collectors'] in declared order
    and produces one AdapterResult per tool. The order is deterministic
    so downstream consumers (scope ledger, report renderer) see a
    stable layout.

    Note: ``detection`` is currently unused because Wave 1 dispatches
    by stack name (``run_adapters`` looks up the stack in the registry)
    rather than per-StackProfile. Wave 5 will use ``detection`` to scope
    each invocation to ``StackProfile.root_dir`` for monorepo workspace
    isolation. Until then, ``repo_path`` is treated as the scan root.
    """
    results: list[AdapterResult] = []
    required = ADAPTER_CONFIG.get("required_collectors", [])
    tools_cfg = ADAPTER_CONFIG.get("tools", {})

    # One tempdir + env for the whole adapter run — the four tools share
    # a single cache redirection root. Cleanup is automatic on context
    # exit via scan_tempdir().
    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        for tool_name in required:
            tool_cfg = tools_cfg.get(tool_name)
            if tool_cfg is None:
                results.append(
                    _make_unavailable(
                        tool_name,
                        "",
                        f"{tool_name} listed in required_collectors but no "
                        f"`tools.{tool_name}` block in adapter.yaml",
                    )
                )
                continue
            # File-reader vs subprocess branch.
            try:
                if tool_cfg.get("command") is None:
                    results.append(
                        _run_file_reader_tool(tool_name, tool_cfg, repo_path)
                    )
                else:
                    results.append(
                        _run_subprocess_tool(
                            tool_name, tool_cfg, repo_path, tempdir, env
                        )
                    )
            except Exception as exc:  # noqa: BLE001 — D-25 backstop
                # Defence in depth: a bug in the per-tool helper itself
                # must not escape the adapter.
                results.append(
                    _make_unavailable(
                        tool_name,
                        tool_cfg.get("dimension", ""),
                        f"{tool_name} dispatcher raised {type(exc).__name__}: {exc}",
                    )
                )

    return results


__all__ = [
    "ADAPTER_CONFIG",
    "CONFIG",
    "detect_eslint_config",
    "run",
]
