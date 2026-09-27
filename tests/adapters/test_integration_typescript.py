"""Phase 3 integration tests — TWO module-level gates.

1. ``pytest.importorskip("repo_audit.adapters")`` — SKIP until Wave 1 lands.
2. ``pytestmark = pytest.mark.integration`` — SKIP under default ``pytest -q``;
   opt-in via ``pytest -m integration``.

Default suite (``pytest -q``) skips on (1) until Wave 1 lands; once Wave 1
lands, default suite skips on (2). Live integration runs require an actual
TS toolchain in ``<repo>/node_modules/.bin/`` (verified live in 03-RESEARCH
against the checkout named by ``$REPO_AUDIT_LIVE_TARGET``).

The canonical SC-6 live-binary check (``test_post_scan_repo_clean``) lives
here per checker Warning 10. A host-independent unit-test counterpart lives
at ``tests/adapters/test_post_scan_repo_clean_unit.py``.

DI-03-03-01 closure (Plan 03-05):
    The previous Wave 0b scaffolding did NOT import the TS adapter package,
    so ``@register_adapter("typescript-node")`` never fired and the registry
    was empty for the test process. Plan 03-05 adds the one-line side-effect
    import at the top of this file (``from repo_audit.adapters import
    typescript``) which closes DI-03-03-01. Additionally, the
    ``test_scope_ledger_includes_adapter_unavailable_rows`` assertion is
    reshaped to look at the lcov Finding's ``evidence_type`` rather than
    the (now-correctly-``ok``) AdapterResult.status — per the D-44 design
    plan 03-03 implemented.
"""
from __future__ import annotations

import subprocess

import pytest

pytest.importorskip(
    "repo_audit.adapters",
    reason="optional module repo_audit.adapters not importable — feature not present in this build, or the install is incomplete",
)

# DI-03-03-01 closure: side-effect import triggers
# ``@register_adapter("typescript-node")`` so run_adapters() actually
# dispatches the TS adapter when this test module runs.
from repo_audit.adapters import typescript as _ts_adapter  # noqa: E402, F401

# Both gates apply: importorskip miss OR missing integration marker ⇒ SKIP.
pytestmark = pytest.mark.integration

from repo_audit.adapters import run_adapters  # noqa: E402
from repo_audit.detect.detector import detect_stacks  # noqa: E402


def test_full_scan_emits_real_findings(ts_fixture_repo):
    """End-to-end: a TS fixture repo with real tsc/eslint/knip in node_modules
    produces a non-empty results list."""
    detection = detect_stacks(ts_fixture_repo)
    results = run_adapters(ts_fixture_repo, detection)
    assert len(results) >= 1


def test_post_scan_repo_clean(ts_fixture_repo_with_tools):
    """SC-6 / D-46 LIVE-BINARY check: post-scan ``git status --porcelain -uall`` is empty.

    This is the canonical location per checker Warning 10. The unit-test
    counterpart at ``test_post_scan_repo_clean_unit.py`` provides the same
    structural guarantee under pytest-subprocess mocking so the default suite
    can verify SC-6 without a live toolchain.

    Runs the full ``repo-audit scan`` CLI flow against a tmp_path fixture whose
    ``node_modules`` symlinks to the dogfood checkout so the adapter actually
    invokes tsc/eslint/knip. Asserts that no files outside permitted
    surfaces (``docs/state-reports/`` is expected output) show up in
    ``git status --porcelain -uall``.
    """
    from typer.testing import CliRunner
    from repo_audit.cli import app

    repo = ts_fixture_repo_with_tools
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0, f"scan failed: {result.output}"
    cp = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain", "-uall"],
        capture_output=True, text=True, check=True,
    )
    offenders = [
        line for line in cp.stdout.splitlines()
        if line.strip()
        and "docs/state-reports" not in line
    ]
    assert offenders == [], (
        f"D-46 cache-redirection failed; SC-6 violated — files outside "
        f"docs/state-reports/: {offenders}"
    )


def test_full_scan_emits_tsc_findings(ts_fixture_repo_with_tools):
    """SC-1 LIVE-BINARY: a TS fixture with a known type error → tsc Finding emitted.

    Adds ``broken.ts`` (``const x: string = 1;``) to the symlinked-tools
    fixture, then invokes ``run_adapters`` directly. Asserts the tsc
    AdapterResult contains at least one Finding with ``source_tool='tsc'``
    and ``dimension='correctness'`` (per plan 03-03's parser contract).
    """
    repo = ts_fixture_repo_with_tools
    (repo / "broken.ts").write_text(
        "const x: string = 1;\n", encoding="utf-8",
    )
    detection = detect_stacks(repo)
    results = run_adapters(repo, detection)
    tsc_results = [r for r in results if r.source_tool == "tsc"]
    assert len(tsc_results) == 1, (
        f"Expected exactly one tsc AdapterResult; got {len(tsc_results)}"
    )
    tsc_findings = tsc_results[0].findings
    assert any(
        f.source_tool == "tsc" and f.dimension == "correctness"
        for f in tsc_findings
    ), (
        f"Expected at least one tsc Finding with dimension='correctness'; "
        f"got {len(tsc_findings)} findings: "
        f"{[(f.source_tool, f.dimension) for f in tsc_findings]}"
    )


def test_scope_ledger_includes_adapter_unavailable_rows(ts_fixture_repo_no_lcov):
    """DI-03-03-01 closure: lcov-missing fixture surfaces an ``unavailable`` Finding.

    Reshaped from the original Wave 0b assertion (``status == 'unavailable'``)
    per the deferred-items entry. The D-44 design (plan 03-03) is: the lcov
    file-reader returns ``AdapterResult(status='ok')`` with the unavailable
    Finding INSIDE (``findings[0].evidence_type == 'unavailable'``). The
    AdapterResult status carries "did the adapter dispatch succeed?" — which
    it did. The Finding's ``evidence_type`` carries "was the artifact
    usable?" — which it was not.
    """
    detection = detect_stacks(ts_fixture_repo_no_lcov)
    results = run_adapters(ts_fixture_repo_no_lcov, detection)
    cov_results = [r for r in results if r.source_tool == "coverage_lcov"]
    assert len(cov_results) == 1
    ar = cov_results[0]
    assert ar.status == "ok", (
        f"file-reader path returns ok; unavailability lives in the Finding. "
        f"Got status={ar.status!r}, notes={ar.notes!r}"
    )
    assert len(ar.findings) == 1
    assert ar.findings[0].evidence_type == "unavailable"
    assert ar.findings[0].rule_id == "coverage_unavailable"
