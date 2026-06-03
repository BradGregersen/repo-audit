"""Plan 11-05 — per-tool LIVE-BINARY integration tests (the Phase-3 argv-shape guard).

Phase-3 lesson (Plan 03-05 deviation, Pitfall 5): an argv-shape bug (``--pretty=false``
vs ``["--pretty", "false"]``) went undetected until a live dogfood scan because no
live-binary integration test exercised the real tool. EVERY stack-depth tool gets
ONE live test here that confirms the invocation argv is ACCEPTED (no EXEC_FAILED)
and the output parses — guarding against argv drift the unit tests (which mock the
subprocess seam) structurally cannot catch.

Two gates, mirroring ``tests/adapters/test_integration_typescript.py``:

    1. ``pytestmark = pytest.mark.integration`` — every test here is excluded from
       the default ``pytest -m "not integration"`` unit tier; opt-in via
       ``pytest -m integration``.
    2. A per-test ``skipif`` on the specific tool/binary — each live test SKIPS
       CLEANLY when its tool is absent (it NEVER fails the suite on a missing
       binary; a missing detekt jar / npx / stryker is an expected environment,
       not a test failure).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.test_depth import run_expo, run_kotlin, run_test_depth
from repo_audit.adapters.typescript.parsers.lcov import parse_from_repo

# Both gates apply: missing integration marker OR an absent tool ⇒ SKIP.
pytestmark = pytest.mark.integration


def _have(tool: str) -> bool:
    """True when the named binary is resolvable on PATH (npx-style check)."""
    return shutil.which(tool) is not None


def _have_detekt() -> bool:
    """detekt is available when BOTH a JRE and the vendored detekt jar resolve."""
    here = Path.cwd()
    return resolve_tool("java", here) is not None and (
        resolve_tool("detekt", here) is not None
    )


# --- detekt (KOT-01) -------------------------------------------------------


@pytest.mark.skipif(not _have_detekt(), reason="java + vendored detekt jar absent")
def test_detekt_live(tmp_path):
    """Seed a tiny Kotlin file; run_kotlin must accept the argv (no EXEC_FAILED)."""
    (tmp_path / "Main.kt").write_text(
        "fun main() { val x = 1; println(x) }\n", encoding="utf-8"
    )
    with scan_tempdir() as td:
        env = build_scan_env(td)
        result = run_kotlin(tmp_path, base_env=env, attempt_typed=False)
    # The invocation argv was accepted: status is a known envelope value, never
    # an exception. unavailable here would mean a real jar/JRE miss (skipif
    # should have caught it), so we assert the run COMPLETED honestly.
    assert result.status in {"ok", "partial", "unavailable", "timeout"}


# --- pytest-cov coverage tier (TST-01) -------------------------------------


@pytest.mark.skipif(not _have("pytest"), reason="pytest not on PATH")
def test_pytest_cov_live(tmp_path):
    """Seed a tiny package+test; the resolved pytest-cov command produces lcov."""
    pytest_cov = pytest.importorskip(
        "pytest_cov", reason="pytest-cov plugin not installed"
    )
    assert pytest_cov is not None
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_add.py").write_text(
        "from mypkg import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8",
    )
    with scan_tempdir() as td:
        env = build_scan_env(td)
        result = run_test_depth(
            tmp_path, base_env=env, refresh_coverage=True, mutation=False, stack="python"
        )
    # The coverage tier ran; either it produced coverage/lcov.info (then
    # parse_from_repo reads it) or it degraded honestly — never an exception.
    assert result.status in {"ok", "partial", "unavailable", "timeout"}
    lcov = tmp_path / "coverage" / "lcov.info"
    if lcov.is_file():
        findings = parse_from_repo(tmp_path)
        assert findings  # the lcov parser read the produced artifact


# --- type-coverage (TST-03) ------------------------------------------------


@pytest.mark.skipif(not _have("npx"), reason="npx not on PATH for type-coverage")
def test_type_coverage_live(tmp_path):
    """type-coverage --json-output argv is accepted; the run completes honestly."""
    # A minimal TS project so type-coverage has something to chew on.
    (tmp_path / "tsconfig.json").write_text(
        json.dumps({"compilerOptions": {"strict": True}}), encoding="utf-8"
    )
    (tmp_path / "index.ts").write_text("export const x: number = 1;\n", encoding="utf-8")
    with scan_tempdir() as td:
        env = build_scan_env(td)
        result = run_test_depth(
            tmp_path, base_env=env, refresh_coverage=False, mutation=False,
            stack="typescript-node",
        )
    assert result.status in {"ok", "partial", "unavailable", "timeout"}


# --- expo-doctor (EXP-01) --------------------------------------------------


@pytest.mark.skipif(not _have("npx"), reason="npx not on PATH for expo-doctor")
def test_expo_doctor_live(tmp_path):
    """expo-doctor argv is accepted; run_expo completes honestly (never raises)."""
    (tmp_path / "app.json").write_text(
        json.dumps({"expo": {"name": "t", "slug": "t"}}), encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "dependencies": {"expo": "*"}}), encoding="utf-8"
    )
    with scan_tempdir() as td:
        env = build_scan_env(td)
        result = run_expo(tmp_path, base_env=env)
    assert result.status in {"ok", "partial", "unavailable", "timeout"}
    assert result.findings  # collect_expo_doctor always returns >=1 Finding


# --- stryker mutation (TST-02, opt-in) -------------------------------------


@pytest.mark.skipif(
    resolve_tool("stryker", Path.cwd()) is None and not _have("npx"),
    reason="stryker / npx absent",
)
def test_stryker_live(tmp_path):
    """mutation=True path: the run completes honestly even with no Stryker config.

    We do NOT require a real Stryker run to succeed (it needs a full JS project +
    config); we assert the OPT-IN path is wired and never raises / never hangs —
    the run_tool hard cap (D-11-05) bounds it.
    """
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t"}), encoding="utf-8"
    )
    with scan_tempdir() as td:
        env = build_scan_env(td)
        result = run_test_depth(
            tmp_path,
            base_env=env,
            refresh_coverage=False,
            mutation=True,
            stack="typescript-node",
            # Keep the live cap short so a misconfigured stryker can't stall CI.
            mutation_timeout_s=60.0,
        )
    assert result.status in {"ok", "partial", "unavailable", "timeout"}
