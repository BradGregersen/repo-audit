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


# --- Task 2 (W1): not-applicable applicability probe -----------------------


def test_run_kotlin_not_applicable_on_non_kotlin_repo(monkeypatch, tmp_path):
    """W1: a repo with no gradle build files → run_kotlin status='not_applicable'.

    detekt is NOT applicable when the repo has no ``build.gradle`` /
    ``build.gradle.kts``; the step short-circuits to ``not_applicable`` (a
    disclosed-but-non-degrading status) WITHOUT invoking collect_detekt. Fails on
    the pre-change code where the absent tool mapped to ``unavailable``.
    """

    def _must_not_run(repo_path, env, **kwargs):
        raise AssertionError("collect_detekt invoked on a non-Kotlin repo")

    monkeypatch.setattr(test_depth, "collect_detekt", _must_not_run)
    result = run_kotlin(tmp_path, base_env={})
    assert result.status == "not_applicable"
    assert result.findings == []
    # The skip is disclosed in the ledger (SAFE-08 honesty).
    assert any("not applicable" in n.lower() for n in result.ledger_notes)


def test_run_kotlin_applicable_when_gradle_present(monkeypatch, tmp_path):
    """W1: a build.gradle.kts present → the applicability probe lets detekt run.

    Proves the probe does NOT swallow a real Kotlin repo: with a gradle build file
    present, collect_detekt is invoked and its (unavailable) status is honored —
    NOT short-circuited to not_applicable.
    """
    (tmp_path / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")

    def _no_detekt(repo_path, env, **kwargs):
        return KotlinResult(status="unavailable", notes="java/JRE not found")

    monkeypatch.setattr(test_depth, "collect_detekt", _no_detekt)
    result = run_kotlin(tmp_path, base_env={})
    assert result.status == "unavailable"  # genuine degradation, NOT not_applicable


def test_run_kotlin_applicable_when_gradle_build_is_in_a_subdirectory(
    monkeypatch, tmp_path
):
    """An Expo or React Native app keeps its Gradle build under ``android/``.

    No build file at the repo root, but a detected Kotlin root holds one: detekt
    runs, still over the whole repo so finding paths stay repo-relative.
    """
    android = tmp_path / "android"
    android.mkdir()
    (android / "build.gradle").write_text("buildscript {}\n", encoding="utf-8")
    called = {}

    def _detekt(repo_path, env, **kwargs):
        called["repo"] = repo_path
        return KotlinResult(status="ok", notes="detekt (standalone): 0 finding(s)")

    monkeypatch.setattr(test_depth, "collect_detekt", _detekt)
    result = run_kotlin(tmp_path, base_env={}, gradle_roots=[android])
    assert result.status == "ok"
    assert called["repo"] == tmp_path


def test_run_kotlin_not_applicable_when_detected_root_has_no_gradle_file(
    monkeypatch, tmp_path
):
    """A detected Kotlin root without a Gradle build file does not make detekt applicable."""
    (tmp_path / "android").mkdir()

    def _must_not_run(repo_path, env, **kwargs):
        raise AssertionError("collect_detekt invoked without a gradle build file")

    monkeypatch.setattr(test_depth, "collect_detekt", _must_not_run)
    result = run_kotlin(tmp_path, base_env={}, gradle_roots=[tmp_path / "android"])
    assert result.status == "not_applicable"


def test_run_expo_not_applicable_on_non_expo_repo(monkeypatch, tmp_path):
    """W1: a repo with no app.json / app.config.* → run_expo status='not_applicable'.

    expo-doctor is NOT applicable when the repo has no Expo manifest; the step
    short-circuits to ``not_applicable`` WITHOUT invoking collect_expo_doctor.
    """

    def _must_not_run(repo_path, env, **kwargs):
        raise AssertionError("collect_expo_doctor invoked on a non-Expo repo")

    monkeypatch.setattr(test_depth, "collect_expo_doctor", _must_not_run)
    result = run_expo(tmp_path, base_env={})
    assert result.status == "not_applicable"
    assert result.findings == []
    assert any("not applicable" in n.lower() for n in result.ledger_notes)


def test_run_expo_applicable_when_app_json_present(monkeypatch, tmp_path):
    """W1: an app.json present → the probe lets expo-doctor run (status honored)."""
    (tmp_path / "app.json").write_text('{"expo": {}}\n', encoding="utf-8")

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
    assert result.status == "unavailable"  # genuine degradation, NOT not_applicable


# --- run_kotlin ------------------------------------------------------------


def test_run_kotlin_absent_jre_unavailable(monkeypatch, tmp_path):
    """No detekt/JRE resolves → run_kotlin status='unavailable', never raises.

    A gradle build file is present so the W1 applicability probe treats this as a
    real Kotlin repo; the absent JRE is then a GENUINE degradation (unavailable),
    distinct from not_applicable.
    """
    (tmp_path / "build.gradle").write_text("plugins {}\n", encoding="utf-8")

    def _no_detekt(repo_path, env, **kwargs):
        return KotlinResult(status="unavailable", notes="java/JRE not found")

    monkeypatch.setattr(test_depth, "collect_detekt", _no_detekt)
    result = run_kotlin(tmp_path, base_env={"PATH": "/usr/bin"})
    assert isinstance(result, TestDepthScanResult)
    assert result.status == "unavailable"
    assert result.findings == []


def test_run_kotlin_never_raises_on_exception(monkeypatch, tmp_path):
    """collect_detekt raising → run_kotlin folds to unavailable, never raises."""
    (tmp_path / "build.gradle").write_text("plugins {}\n", encoding="utf-8")

    def _boom(repo_path, env, **kwargs):
        raise RuntimeError("detekt blew up")

    monkeypatch.setattr(test_depth, "collect_detekt", _boom)
    result = run_kotlin(tmp_path, base_env={})
    assert result.status == "unavailable"


# --- run_expo --------------------------------------------------------------


def test_expo_unavailable_completes(monkeypatch, tmp_path):
    """expo-doctor absent → run_expo unavailable, no raise.

    An app.json is present so the W1 applicability probe treats this as a real
    Expo repo; the absent tool is then a GENUINE degradation (unavailable).
    """
    (tmp_path / "app.json").write_text('{"expo": {}}\n', encoding="utf-8")

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


# --- Task 1 (B3): injected node coverage enables the WEAK signal ------------


def test_injected_line_pct_enables_weak_signal_for_node(monkeypatch, tmp_path):
    """B3: injected_line_pct + mutation → WEAK signal fires WITHOUT the in-step tier.

    A node stack gates its in-step coverage tier OFF in scan_runner (the lcov
    refresh runs out-of-band via ``_maybe_refresh_coverage``). So the only way the
    D-11-06 WEAK signal can fire for node + --mutation is if the executed line_pct
    is THREADED IN. With ``injected_line_pct=90.0`` and a mutation score of 50.0
    (1 killed / 2 valid), the gap is 40 >= 25 → exactly one weak_tests Finding.

    Fails on the pre-change code (no ``injected_line_pct`` param; coverage_line_pct
    can never be populated for a node stack whose in-step coverage tier is skipped).
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

    result = run_test_depth(
        tmp_path,
        base_env={},
        refresh_coverage=False,  # node in-step coverage tier intentionally OFF
        mutation=True,
        stack="typescript-node",
        injected_line_pct=90.0,
    )
    weak = [f for f in result.findings if f.rule_id == "weak_tests"]
    assert len(weak) == 1
    assert "cross_link" in weak[0].evidence.parsed_value


def test_in_step_coverage_wins_over_injected_no_double_weak(monkeypatch, tmp_path):
    """B3: when BOTH the in-step tier AND an injected value exist, exactly one WEAK.

    The in-step measured value (this step's own coverage tier) takes precedence over
    the injected one — they refer to the same metric. With the in-step tier yielding
    90% and an injected 10% both present + a mutation score of 50, at most ONE
    weak_tests Finding is emitted (the 90-vs-50 gap), never two.
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
    # In-step coverage tier yields a 90% line_pct Finding (this wins over injected).
    monkeypatch.setattr(
        test_depth, "_run_coverage_tier",
        lambda *a, **k: ([_coverage_finding(90.0)], "ok", []),
    )

    result = run_test_depth(
        tmp_path,
        base_env={},
        refresh_coverage=True,  # in-step tier runs
        mutation=True,
        stack="python",
        injected_line_pct=10.0,  # injected; must be superseded by the in-step 90%
    )
    weak = [f for f in result.findings if f.rule_id == "weak_tests"]
    assert len(weak) == 1


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


# --- Task 3 (W2): node-gate the type-coverage npx fallback ------------------


def test_type_coverage_no_npx_on_non_node_stack(monkeypatch, tmp_path):
    """W2: non-node stack + no local binary → unavailable, NO npx egress.

    On ``stack="python"`` with ``resolve_tool`` returning None, the type-coverage
    tier must NOT shell out to ``npx type-coverage`` (a network fetch + arbitrary
    package execution surface). It degrades to unavailable instead.
    """
    calls: list[list] = []

    def _record(argv, **kw):
        calls.append(list(argv))
        return _Inv(0, stdout="")

    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)
    monkeypatch.setattr(test_depth, "run_tool", _record)

    result = run_test_depth(
        tmp_path, base_env={}, refresh_coverage=False, mutation=False, stack="python"
    )
    npx_calls = [c for c in calls if c and "npx" in str(c[0])]
    assert npx_calls == [], f"npx egress fired on a non-node stack: {npx_calls}"
    assert isinstance(result, TestDepthScanResult)


def test_type_coverage_npx_allowed_on_node_stack(monkeypatch, tmp_path):
    """W2: node stack + no local binary → npx fallback still permitted.

    type-coverage belongs to node — on ``stack="typescript-node"`` with no local
    binary the npx fallback is allowed (an empty stdout still degrades gracefully,
    but the argv must have been the npx invocation).
    """
    calls: list[list] = []

    def _record(argv, **kw):
        calls.append(list(argv))
        return _Inv(0, stdout="")

    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)
    monkeypatch.setattr(test_depth, "run_tool", _record)

    run_test_depth(
        tmp_path, base_env={}, refresh_coverage=False, mutation=False,
        stack="typescript-node",
    )
    npx_calls = [c for c in calls if c and "npx" in str(c[0])]
    assert len(npx_calls) == 1, f"expected the npx fallback on a node stack: {calls}"


# --- Task 3 (W3): no stale coverage numbers on a failed refresh -------------


def test_failed_refresh_does_not_emit_concrete_coverage(monkeypatch, tmp_path):
    """W3: refresh status != 'ok' → no concrete-percentage coverage_summary Finding.

    A failed coverage refresh must not present a pre-existing on-disk coverage
    percentage as THIS run's result. The tier degrades (partial/unavailable) and the
    parsed concrete-percentage Finding is NOT surfaced. Fails on the pre-change code
    which parsed-and-emitted the on-disk artifact regardless of refresh status.
    """
    monkeypatch.setattr(
        test_depth.refresh, "resolve_runner_command",
        lambda repo, *, stack, override=None: ["pytest", "--cov"],
    )

    class _RR:
        status = "failed"
        lcov_produced = False

    monkeypatch.setattr(
        test_depth.refresh, "refresh_coverage", lambda repo, cfg, env: _RR()
    )
    # The on-disk artifact would parse to a concrete 80% — it must NOT be surfaced.
    monkeypatch.setattr(
        test_depth, "parse_from_repo", lambda repo: [_coverage_finding(80.0)]
    )
    monkeypatch.setattr(
        test_depth, "parse_kover_xml", lambda repo: [_coverage_finding(80.0)]
    )
    monkeypatch.setattr(test_depth, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(test_depth, "diff_git_status", lambda pre, post, **kw: [])
    monkeypatch.setattr(test_depth, "resolve_tool", lambda tool, repo: None)

    result = run_test_depth(
        tmp_path, base_env={}, refresh_coverage=True, mutation=False, stack="python"
    )
    concrete = [
        f
        for f in result.findings
        if f.rule_id == "coverage_summary"
        and isinstance(f.evidence.parsed_value.get("line_pct"), (int, float))
    ]
    assert concrete == [], "stale on-disk coverage percentage surfaced on a failed refresh"
    assert result.status in {"partial", "unavailable"}
