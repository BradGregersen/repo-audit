"""Plan 11-05 Task 1 — run_test_depth / run_kotlin / run_expo contract tests.

These exercise the three cross-stack steps in ``adapters/test_depth.py``:

    * ``run_kotlin``  — never-raising detekt envelope (KOT-01).
    * ``run_expo``    — never-raising expo-doctor envelope (EXP-01).
    * ``run_test_depth`` — composes the coverage / mutation / type-coverage tiers
      (TST-01/02/03), each independently never-raising, with the D-11-02
      tracked-files-only git tripwire bracketing the in-place coverage/mutation
      runs and mutation gated opt-in (D-11-03).

The module-level seams (``resolve_tool``, ``run_tool``, ``snapshot_git_status``,
``diff_git_status``, ``collect_detekt``, ``collect_expo_doctor``,
``refresh.*``, ``parse_*``) are monkeypatched so no real JVM / binary / git I/O
is needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_audit.adapters import test_depth
from repo_audit.adapters.kotlin import KotlinResult
from repo_audit.adapters.test_depth import (
    TestDepthScanResult,
    run_expo,
    run_kotlin,
    run_test_depth,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT
from repo_audit.schema.finding import Evidence, Finding


def _coverage_finding(line_pct: float) -> Finding:
    """A minimal lcov-shaped aggregate coverage Finding (rule_id=coverage_summary)."""
    return Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="static",
        confidence="candidate",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_summary",
        recommendation=f"{line_pct}% line coverage executed.",
        evidence=Evidence(
            tool="lcov",
            output_snippet=f"lcov: {line_pct}% line",
            parsed_value={"line_pct": line_pct, "total_pct": line_pct},
        ),
    )


class _Inv:
    """A minimal InvocationResult stand-in for monkeypatched run_tool."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- run_kotlin ------------------------------------------------------------


def test_run_kotlin_absent_jre_unavailable(monkeypatch, tmp_path):
    """No detekt/JRE resolves → run_kotlin status='unavailable', never raises."""

    def _no_detekt(repo_path, env, **kwargs):
        return KotlinResult(status="unavailable", notes="java/JRE not found")

    monkeypatch.setattr(test_depth, "collect_detekt", _no_detekt)
    result = run_kotlin(tmp_path, base_env={"PATH": "/usr/bin"})
    assert isinstance(result, TestDepthScanResult)
    assert result.status == "unavailable"
    assert result.findings == []


def test_run_kotlin_never_raises_on_exception(monkeypatch, tmp_path):
    """collect_detekt raising → run_kotlin folds to unavailable, never raises."""

    def _boom(repo_path, env, **kwargs):
        raise RuntimeError("detekt blew up")

    monkeypatch.setattr(test_depth, "collect_detekt", _boom)
    result = run_kotlin(tmp_path, base_env={})
    assert result.status == "unavailable"


# --- run_expo --------------------------------------------------------------


def test_expo_unavailable_completes(monkeypatch, tmp_path):
    """expo-doctor absent → run_expo unavailable, no raise."""

    def _no_expo(repo_path, env, **kwargs):
        return [
            Finding(
                dimension="quality",
                severity="minor",
                evidence_type="unavailable",
                confidence="candidate",
                source_tool="expo-doctor",
                source_collector="expo_doctor",
                rule_id="expo_doctor_unavailable",
                recommendation="expo-doctor not run.",
                evidence=Evidence(
                    tool="expo-doctor",
                    output_snippet="absent",
                    parsed_value={"reason": "expo_doctor_unavailable"},
                ),
            )
        ]

    monkeypatch.setattr(test_depth, "collect_expo_doctor", _no_expo)
    result = run_expo(tmp_path, base_env={})
    assert isinstance(result, TestDepthScanResult)
    assert result.status == "unavailable"
    assert len(result.findings) == 1


# --- run_test_depth: mutation gating (D-11-03) -----------------------------


def test_mutation_not_run_by_default(monkeypatch, tmp_path):
    """mutation=False → Stryker is NEVER invoked and no mutation Finding appears."""

    def _explode_if_stryker(argv, **kwargs):
        if any("stryker" in str(a) for a in argv):
            raise AssertionError("stryker invoked despite mutation=False (D-11-03)")
        return _Inv(0, stdout="")

    monkeypatch.setattr(test_depth, "run_tool", _explode_if_stryker)
    # Resolve type-coverage so its tier runs but produces nothing surprising.
    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)

    result = run_test_depth(tmp_path, base_env={}, refresh_coverage=False, mutation=False)
    assert isinstance(result, TestDepthScanResult)
    assert not any(
        f.rule_id == "mutation_score" for f in result.findings
    )


def test_mutation_opt_in_computes_finding(monkeypatch, tmp_path):
    """mutation=True + a mutation.json → exactly one mutation_score Finding."""
    report = {
        "files": {
            "a.ts": {
                "mutants": [
                    {"status": "Killed"},
                    {"status": "Survived"},
                ]
            }
        }
    }

    reports_dir = tmp_path / "reports" / "mutation"
    reports_dir.mkdir(parents=True)
    (reports_dir / "mutation.json").write_text(json.dumps(report), encoding="utf-8")

    def _resolve(tool, repo):
        return Path("/usr/bin/stryker") if tool == "stryker" else None

    monkeypatch.setattr(test_depth, "resolve_tool", _resolve)
    monkeypatch.setattr(test_depth, "run_tool", lambda argv, **kw: _Inv(0, stdout="ok"))
    # No tracked-file change (tripwire clean).
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])

    result = run_test_depth(tmp_path, base_env={}, mutation=True)
    mutation_findings = [f for f in result.findings if f.rule_id == "mutation_score"]
    assert len(mutation_findings) == 1
    assert mutation_findings[0].evidence.parsed_value["run_status"] == "ok"


def test_mutation_timeout_partial(monkeypatch, tmp_path):
    """Stryker TIMED_OUT with a partial mutation.json → partial mutation Finding."""
    report = {"files": {"a.ts": {"mutants": [{"status": "Killed"}]}}}
    reports_dir = tmp_path / "reports" / "mutation"
    reports_dir.mkdir(parents=True)
    (reports_dir / "mutation.json").write_text(json.dumps(report), encoding="utf-8")

    def _resolve(tool, repo):
        return Path("/usr/bin/stryker") if tool == "stryker" else None

    monkeypatch.setattr(test_depth, "resolve_tool", _resolve)
    monkeypatch.setattr(test_depth, "run_tool", lambda argv, **kw: _Inv(TIMED_OUT))
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])

    result = run_test_depth(tmp_path, base_env={}, mutation=True)
    mutation_findings = [f for f in result.findings if f.rule_id == "mutation_score"]
    assert len(mutation_findings) == 1
    assert mutation_findings[0].evidence.parsed_value["run_status"] == "partial"


# --- Task 2 (B2): mutation success gated on returncode == 0 -----------------


def test_mutation_stale_report_on_error_exit_not_trusted(monkeypatch, tmp_path):
    """rc=1 (Stryker error exit) + a stale mutation.json → NO confident ok Finding.

    A complete prior-run ``mutation.json`` is on disk, but THIS Stryker run errored
    (rc=1, not a sentinel). The success branch must NOT fire — the tier degrades to
    unavailable and the ledger names the non-zero exit. Fails on the pre-change code
    where rc=1 fell into the unconditional ``else`` and emitted ``status="ok"``.
    """
    report = {
        "files": {
            "a.ts": {
                "mutants": [{"status": "Killed"}, {"status": "Survived"}]
            }
        }
    }
    reports_dir = tmp_path / "reports" / "mutation"
    reports_dir.mkdir(parents=True)
    (reports_dir / "mutation.json").write_text(json.dumps(report), encoding="utf-8")

    def _resolve(tool, repo):
        return Path("/usr/bin/stryker") if tool == "stryker" else None

    monkeypatch.setattr(test_depth, "resolve_tool", _resolve)
    monkeypatch.setattr(test_depth, "run_tool", lambda argv, **kw: _Inv(1, stderr="boom"))
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])

    result = run_test_depth(tmp_path, base_env={}, mutation=True)
    ok_findings = [
        f
        for f in result.findings
        if f.rule_id == "mutation_score"
        and f.evidence.parsed_value.get("run_status") == "ok"
    ]
    assert ok_findings == [], "a confident ok mutation Finding leaked from an errored run"
    assert any("non-zero" in n or "exited non-zero" in n for n in result.ledger_notes)


def test_mutation_clean_success_still_emits_ok(monkeypatch, tmp_path):
    """rc=0 + a valid mutation.json → exactly one confident ok mutation Finding.

    Regression-proofs the happy path is unaffected by the returncode==0 guard.
    """
    report = {
        "files": {
            "a.ts": {
                "mutants": [{"status": "Killed"}, {"status": "Survived"}]
            }
        }
    }
    reports_dir = tmp_path / "reports" / "mutation"
    reports_dir.mkdir(parents=True)
    (reports_dir / "mutation.json").write_text(json.dumps(report), encoding="utf-8")

    def _resolve(tool, repo):
        return Path("/usr/bin/stryker") if tool == "stryker" else None

    monkeypatch.setattr(test_depth, "resolve_tool", _resolve)
    monkeypatch.setattr(test_depth, "run_tool", lambda argv, **kw: _Inv(0))
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])

    result = run_test_depth(tmp_path, base_env={}, mutation=True)
    ok_findings = [
        f
        for f in result.findings
        if f.rule_id == "mutation_score"
        and f.evidence.parsed_value.get("run_status") == "ok"
    ]
    assert len(ok_findings) == 1


# --- run_test_depth: WEAK signal (D-11-06) ---------------------------------


def test_weak_signal_emitted_on_gap(monkeypatch, tmp_path):
    """coverage line_pct=90 + mutation score=50 → a weak_tests Finding cross-linked."""
    # mutation.json computes to score 50.0 (1 killed / 2 valid).
    report = {
        "files": {
            "a.ts": {
                "mutants": [{"status": "Killed"}, {"status": "Survived"}]
            }
        }
    }
    reports_dir = tmp_path / "reports" / "mutation"
    reports_dir.mkdir(parents=True)
    (reports_dir / "mutation.json").write_text(json.dumps(report), encoding="utf-8")

    def _resolve(tool, repo):
        return Path("/usr/bin/stryker") if tool == "stryker" else None

    monkeypatch.setattr(test_depth, "resolve_tool", _resolve)
    monkeypatch.setattr(test_depth, "run_tool", lambda argv, **kw: _Inv(0))
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])
    # Coverage tier yields a 90% line_pct Finding.
    monkeypatch.setattr(
        test_depth, "_run_coverage_tier",
        lambda *a, **k: ([_coverage_finding(90.0)], "ok", []),
    )

    result = run_test_depth(
        tmp_path, base_env={}, refresh_coverage=True, mutation=True
    )
    weak = [f for f in result.findings if f.rule_id == "weak_tests"]
    assert len(weak) == 1
    assert "cross_link" in weak[0].evidence.parsed_value


# --- run_test_depth: tripwire (D-11-02) ------------------------------------


def test_tripwire_downgrades_on_tracked_change(monkeypatch, tmp_path):
    """A tracked-file offender downgrades the coverage tier to partial + names it."""
    # Resolve a coverage runner and make refresh_coverage 'succeed'.
    monkeypatch.setattr(
        test_depth.refresh, "resolve_runner_command",
        lambda repo, *, stack, override=None: ["pytest", "--cov"],
    )

    class _RR:
        status = "ok"
        lcov_produced = True

    monkeypatch.setattr(
        test_depth.refresh, "refresh_coverage", lambda repo, cfg, env: _RR()
    )
    monkeypatch.setattr(test_depth, "parse_from_repo", lambda repo: [_coverage_finding(80.0)])
    # Tripwire fires: snapshot differs and diff names an offender.
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(
        test_depth, "diff_git_status",
        lambda pre, post, **kw: [" M src/touched_by_runner.py"],
    )

    result = run_test_depth(
        tmp_path, base_env={}, refresh_coverage=True, mutation=False, stack="python"
    )
    # The overall status reflects the downgraded coverage tier (partial).
    assert result.status in {"partial", "unavailable"}
    assert any("touched_by_runner.py" in n for n in result.ledger_notes)


def test_run_test_depth_never_raises(monkeypatch, tmp_path):
    """A tier blowing up internally never propagates out of run_test_depth."""

    def _boom(*a, **k):
        raise RuntimeError("tier exploded")

    monkeypatch.setattr(test_depth, "_run_coverage_tier", _boom)
    monkeypatch.setattr(test_depth, "_run_type_coverage_tier", _boom)
    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)
    result = run_test_depth(tmp_path, base_env={}, refresh_coverage=True, mutation=False)
    assert isinstance(result, TestDepthScanResult)


# --- Task 1 (B1): Kotlin stack literal drift guard + kover-branch reach ------


def test_kotlin_stack_literal_matches_detector_tag():
    """Drift guard: ``_KOTLIN_STACK`` MUST equal the detector's emitted Kotlin tag.

    The detector (``detect/rules.py``) emits ``kotlin-android``; the coverage tier
    compares the resolved stack against ``_KOTLIN_STACK`` to pick kover-vs-lcov. If
    these drift apart the kover path goes dead. This pins the constant to the
    detector's source-of-truth rule name (Phase-3 ``test_stack_name_binding.py``
    precedent: assert-against-detector, never hardcode a third copy).
    """
    from repo_audit.detect.rules import MANIFEST_RULES

    kotlin_rules = [r for r in MANIFEST_RULES if "kotlin" in r.name]
    assert len(kotlin_rules) == 1, f"expected exactly one kotlin rule, got {kotlin_rules}"
    assert test_depth._KOTLIN_STACK == kotlin_rules[0].name
    assert test_depth._KOTLIN_STACK == "kotlin-android"


def test_kover_branch_reached_for_detector_kotlin_tag(monkeypatch, tmp_path):
    """stack='kotlin-android' → the kover branch runs (parse_kover_xml), NOT lcov.

    Proves the coverage tier reaches ``parse_kover_xml`` for the REAL detector tag.
    ``parse_from_repo`` (the lcov path) is wired to raise — if the branch picks lcov
    for a kotlin-android repo this test fails (the pre-change bug, where
    ``_KOTLIN_STACK='kotlin'`` never matched the detector's ``kotlin-android``).
    """
    sentinel = _coverage_finding(80.0)

    monkeypatch.setattr(
        test_depth.refresh, "resolve_runner_command",
        lambda repo, *, stack, override=None: ["./gradlew", "koverXmlReport"],
    )

    class _RR:
        status = "ok"
        lcov_produced = True

    monkeypatch.setattr(
        test_depth.refresh, "refresh_coverage", lambda repo, cfg, env: _RR()
    )
    monkeypatch.setattr(test_depth, "parse_kover_xml", lambda repo: [sentinel])

    def _lcov_must_not_run(repo):
        raise AssertionError("parse_from_repo (lcov) called for a kotlin-android repo")

    monkeypatch.setattr(test_depth, "parse_from_repo", _lcov_must_not_run)
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])
    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)

    result = run_test_depth(
        tmp_path, base_env={}, refresh_coverage=True, mutation=False,
        stack="kotlin-android",
    )
    assert sentinel in result.findings


def test_refresh_resolves_kover_for_kotlin_android(tmp_path):
    """refresh.resolve_runner_command(stack='kotlin-android') returns the kover cmd.

    A ``build.gradle.kts`` mentioning kover present → the kover runner is resolved
    (not None). Fails on the pre-change code which branched on ``stack == "kotlin"``.
    """
    (tmp_path / "build.gradle.kts").write_text(
        'plugins { id("org.jetbrains.kotlinx.kover") }\n', encoding="utf-8"
    )
    cmd = test_depth.refresh.resolve_runner_command(
        tmp_path, stack="kotlin-android"
    )
    assert cmd == ["./gradlew", "koverXmlReport"]
