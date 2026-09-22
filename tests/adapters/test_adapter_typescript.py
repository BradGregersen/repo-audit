"""Phase 3 Wave 1/2 contract — SKIP via importorskip until 03-02 + 03-03 land.

Two importorskip gates: the second one fires only after 03-03 puts the
parser-dispatch logic in place. Either miss SKIPS the whole module.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.typescript",
    reason="optional module repo_audit.adapters.typescript not importable — feature not present in this build, or the install is incomplete",
)

# These imports come into scope once Wave 1+2 land.
from repo_audit.adapters.base import AdapterResult  # noqa: E402
from repo_audit.adapters.typescript import (  # noqa: E402
    ADAPTER_CONFIG,
    run as run_ts_adapter,
)


# --- adapter.yaml ingest -------------------------------------------------

def test_adapter_yaml_loaded_at_import():
    """``ADAPTER_CONFIG`` is populated at import-time (module-level YAML load)."""
    assert ADAPTER_CONFIG is not None
    assert isinstance(ADAPTER_CONFIG, dict)


def test_required_collectors_declared():
    """ADAPT-05 / D-39: ``required_collectors`` MUST be a non-empty list."""
    assert "required_collectors" in ADAPTER_CONFIG
    assert isinstance(ADAPTER_CONFIG["required_collectors"], list)
    assert len(ADAPTER_CONFIG["required_collectors"]) > 0


def test_yaml_loaded_in_safe_mode():
    """T-03-01: adapter.yaml is loaded under ``YAML(typ='safe')``.

    Structural test: import the loader module and check the YAML constructor
    is parameterised as safe. If a future refactor switches to ``YAML()``
    default (unsafe), this fails.
    """
    import inspect
    import repo_audit.adapters.typescript as ts_mod
    src = inspect.getsource(ts_mod)
    assert "YAML(typ=" in src and "safe" in src, (
        "adapter.yaml loader must instantiate ruamel.yaml YAML(typ='safe') — "
        "see T-03-01 in 03-RESEARCH.md."
    )


def test_adapter_registered_under_correct_literal():
    """Plan 03-01a pinned ``typescript-node``; @register_adapter MUST match."""
    from repo_audit.adapters.registry import get_adapter_registry
    assert "typescript-node" in get_adapter_registry()


# --- parser dispatch (D-39) ---------------------------------------------

def test_parser_dispatch():
    """D-39: adapter.yaml maps tool → parser dotted path; loader resolves it."""
    assert "tools" in ADAPTER_CONFIG
    for tool_name, tool_cfg in ADAPTER_CONFIG["tools"].items():
        if "parser" in tool_cfg:
            assert "." in tool_cfg["parser"], (
                f"tool {tool_name!r}: parser path must be dotted, got {tool_cfg['parser']!r}"
            )


# --- eslint config detection ---------------------------------------------

def test_eslint_config_detection_flat(ts_fixture_repo):
    """eslint.config.{js,mjs,cjs} at root ⇒ flat config detected."""
    from repo_audit.adapters.typescript import detect_eslint_config
    cfg = detect_eslint_config(ts_fixture_repo)
    assert cfg in {"flat", "both"}


def test_eslint_config_detection_legacy(tmp_path):
    """.eslintrc.{js,cjs,json,yml} at root ⇒ legacy config detected."""
    from repo_audit.adapters.typescript import detect_eslint_config
    (tmp_path / ".eslintrc.json").write_text("{}\n", encoding="utf-8")
    cfg = detect_eslint_config(tmp_path)
    assert cfg in {"legacy", "both"}


def test_eslint_config_detection_legacy_via_package_json(tmp_path):
    """``package.json: {"eslintConfig": {...}}`` counts as legacy."""
    import json as _json
    from repo_audit.adapters.typescript import detect_eslint_config
    (tmp_path / "package.json").write_text(
        _json.dumps({"name": "x", "eslintConfig": {"rules": {}}}),
        encoding="utf-8",
    )
    cfg = detect_eslint_config(tmp_path)
    assert cfg in {"legacy", "both"}


def test_eslint_config_detection_both(tmp_path):
    """Both flat and legacy present ⇒ ``"both"`` returned (eslint precedence rules apply downstream)."""
    from repo_audit.adapters.typescript import detect_eslint_config
    (tmp_path / "eslint.config.js").write_text("export default [];\n", encoding="utf-8")
    (tmp_path / ".eslintrc.json").write_text("{}\n", encoding="utf-8")
    cfg = detect_eslint_config(tmp_path)
    assert cfg == "both"


def test_eslint_config_detection_none(tmp_path):
    """Repo with no eslint config ⇒ ``None`` (adapter SKIPS eslint, emits unavailable)."""
    from repo_audit.adapters.typescript import detect_eslint_config
    cfg = detect_eslint_config(tmp_path)
    assert cfg is None


# --- end-to-end smoke ----------------------------------------------------

def test_all_tools_missing_scan_still_completes(tmp_path_factory, mock_ts_tools_subprocess):
    """SAFE-04: a target repo with every tool missing STILL produces ``len(results)==4``.

    Each of {tsc, eslint, knip, coverage_lcov} emits an ``unavailable`` AdapterResult
    rather than the adapter raising.
    """
    # mock subprocess returning code 127 (tool not found) by overriding scenarios
    repo = tmp_path_factory.mktemp("no-tools")
    from repo_audit.detect.detector import detect_stacks
    detection = detect_stacks(repo)
    results = run_ts_adapter(repo, detection)
    assert len(results) == 4
    for r in results:
        assert isinstance(r, AdapterResult)


def test_run_returns_four_results_with_correct_source_tool(
    ts_fixture_repo, mock_ts_tools_subprocess,
):
    """Adapter run MUST return exactly 4 results, one per tool."""
    mock_ts_tools_subprocess(tsc="clean", eslint="clean", knip="clean")
    from repo_audit.detect.detector import detect_stacks
    detection = detect_stacks(ts_fixture_repo)
    results = run_ts_adapter(ts_fixture_repo, detection)
    source_tools = {r.source_tool for r in results}
    assert source_tools == {"tsc", "eslint", "knip", "coverage_lcov"}


def test_run_findings_empty_in_wave_1(ts_fixture_repo, mock_ts_tools_subprocess):
    """All-clean scenario ⇒ each AdapterResult.findings is empty (no false positives)."""
    mock_ts_tools_subprocess(tsc="clean", eslint="clean", knip="clean")
    from repo_audit.detect.detector import detect_stacks
    detection = detect_stacks(ts_fixture_repo)
    results = run_ts_adapter(ts_fixture_repo, detection)
    # Coverage may emit one aggregate Finding; tsc/eslint/knip should be empty.
    for r in results:
        if r.source_tool in {"tsc", "eslint", "knip"}:
            assert r.findings == [], f"{r.source_tool} should have 0 findings on clean run"


def test_dimension_routing(ts_fixture_repo, mock_ts_tools_subprocess):
    """Each AdapterResult carries the dimension declared in adapter.yaml."""
    mock_ts_tools_subprocess(tsc="clean", eslint="clean", knip="clean")
    from repo_audit.detect.detector import detect_stacks
    detection = detect_stacks(ts_fixture_repo)
    results = run_ts_adapter(ts_fixture_repo, detection)
    dims = {r.source_tool: r.dimension for r in results}
    # Dimensions are declared in adapter.yaml; this test pins the mapping
    # downstream code relies on (test integrity / quality_debt / architecture_rot / test_integrity).
    expected_dims = {
        "tsc": "quality_debt",
        "eslint": "quality_debt",
        "knip": "architecture_rot",
        "coverage_lcov": "test_integrity",
    }
    for tool, expected in expected_dims.items():
        assert dims.get(tool) == expected, (
            f"{tool} dimension routing mismatch: got {dims.get(tool)!r}, expected {expected!r}"
        )


# --- argv contract guards (Pitfalls 1, 2, 3) ----------------------------

def test_tsc_args_omits_incremental():
    """Pitfall 3: adapter.yaml MUST NOT pass ``--incremental`` to tsc."""
    tsc_args = ADAPTER_CONFIG["tools"]["tsc"].get("args", [])
    assert "--incremental" not in tsc_args


def test_eslint_args_omits_cache():
    """Pitfall 2: adapter.yaml MUST NOT pass ``--cache`` to eslint."""
    eslint_args = ADAPTER_CONFIG["tools"]["eslint"].get("args", [])
    assert "--cache" not in eslint_args


def test_knip_args_omits_no_cache():
    """Pitfall 1: knip has no ``--no-cache`` flag (would crash with usage error)."""
    knip_args = ADAPTER_CONFIG["tools"]["knip"].get("args", [])
    assert "--no-cache" not in knip_args


# --- Plan 03-05 Decision C sub-steps (refresh wiring in cli.py) ----------
#
# These two tests live here (not in test_integration_typescript.py) because
# they mock the refresh runner + lcov parser and therefore do NOT require
# real binaries. The integration-marker file gates live-binary tests; these
# mock-based tests must run under the default suite so the contract for
# sub-step C + sub-step D is enforced on every commit.


def test_refresh_ok_replaces_unavailable_with_fresh_finding(
    monkeypatch, fake_repo, runner
):
    """Decision C sub-step C: refresh success → fresh aggregate REPLACES unavailable.

    Mocks ``parse_from_repo`` to return [unavailable_finding] on first call and
    [fresh_aggregate_finding] on second call. Mocks ``refresh_coverage`` to
    return ``RefreshResult(status='ok', ...)``. Asserts the rendered sidecar
    JSON's findings list contains the fresh aggregate (rule_id='coverage_summary')
    AND does NOT contain the prior unavailable Finding (rule_id='coverage_unavailable').
    """
    import json
    from repo_audit import cli as cli_mod
    from repo_audit.adapters.typescript.parsers import lcov as lcov_mod
    from repo_audit.adapters.typescript import refresh as refresh_mod
    from repo_audit.schema.finding import Evidence, Finding

    unavailable = Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="unavailable",
        confidence="medium",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_unavailable",
        recommendation="run coverage",
        evidence=Evidence(
            tool="lcov-parser",
            output_snippet="missing",
            parsed_value={"reason": "stale_or_missing_coverage_artifact"},
        ),
    )
    fresh = Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="static",
        confidence="high",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_summary",
        recommendation="coverage from lcov",
        confidence_caveat="Static coverage caveat for tests.",
        evidence=Evidence(
            tool="lcov-parser",
            output_snippet="ok",
            parsed_value={
                "total_pct": 80.0,
                "line_pct": 80.0,
                "branch_pct": 50.0,
                "function_pct": 100.0,
                "file_count": 2,
                "artifact_mtime_iso": "2026-05-28T00:00:00+00:00",
            },
        ),
    )

    call_counter = {"n": 0}

    def fake_parse(repo_path):
        call_counter["n"] += 1
        # First pass (the adapter's lcov dispatch) → unavailable.
        # Second pass (cli's sub-step C re-invoke) → fresh aggregate.
        return [fresh] if call_counter["n"] >= 2 else [unavailable]

    # Patch the parser at BOTH import sites so the adapter's first call and
    # cli.py's re-invoke both hit the fake.
    monkeypatch.setattr(lcov_mod, "parse_from_repo", fake_parse)

    def fake_refresh(repo_root, cfg, env):
        return refresh_mod.RefreshResult(
            status="ok",
            runner_command=["npm", "test"],
            duration_ms=1234.5,
            stdout_tail="",
            stderr_tail="",
            lcov_produced=True,
            notes="coverage refreshed",
            exit_code=0,
        )

    monkeypatch.setattr(refresh_mod, "refresh_coverage", fake_refresh)

    repo = fake_repo(
        {"tsconfig.json": "{}", "package.json": '{"name":"x"}'},
        name="refresh-ok",
    )
    result = runner.invoke(
        cli_mod.app, ["scan", "--refresh-coverage", str(repo)],
    )
    assert result.exit_code == 0, f"scan failed: {result.output}"
    json_files = list((repo / "docs" / "state-reports").glob("*.json"))
    assert json_files, "JSON sidecar not written"
    data = json.loads(json_files[0].read_text())
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "coverage_summary" in rule_ids, (
        f"sub-step C must REPLACE with fresh aggregate; got rule_ids={rule_ids}"
    )
    assert "coverage_unavailable" not in rule_ids, (
        f"sub-step C must REMOVE coverage_unavailable; got rule_ids={rule_ids}"
    )


def test_refresh_failed_emits_failed_finding_and_keeps_unavailable(
    monkeypatch, fake_repo, runner
):
    """Decision C sub-step D: refresh failure → 'failed' APPENDED; unavailable KEPT.

    Mocks ``parse_from_repo`` to always return [unavailable_finding]. Mocks
    ``refresh_coverage`` to return ``RefreshResult(status='failed', ...)``.
    Asserts the rendered sidecar JSON's findings list contains BOTH the
    unavailable Finding AND a new ``evidence_type='failed'`` Finding with
    ``rule_id='coverage_refresh_failed'``.
    """
    import json
    from repo_audit import cli as cli_mod
    from repo_audit.adapters.typescript.parsers import lcov as lcov_mod
    from repo_audit.adapters.typescript import refresh as refresh_mod
    from repo_audit.schema.finding import Evidence, Finding

    unavailable = Finding(
        dimension="test_integrity",
        severity="major",
        evidence_type="unavailable",
        confidence="medium",
        source_tool="lcov",
        source_collector="typescript_adapter",
        rule_id="coverage_unavailable",
        recommendation="run coverage",
        evidence=Evidence(
            tool="lcov-parser",
            output_snippet="missing",
            parsed_value={"reason": "stale_or_missing_coverage_artifact"},
        ),
    )
    monkeypatch.setattr(
        lcov_mod, "parse_from_repo", lambda repo_path: [unavailable],
    )

    def fake_refresh(repo_root, cfg, env):
        return refresh_mod.RefreshResult(
            status="failed",
            runner_command=["npm", "test"],
            duration_ms=42.0,
            stdout_tail="",
            stderr_tail="runner exited 1\nerr text",
            lcov_produced=False,
            notes="coverage_refresh_failed: runner exit 1",
            exit_code=1,
        )

    monkeypatch.setattr(refresh_mod, "refresh_coverage", fake_refresh)

    repo = fake_repo(
        {"tsconfig.json": "{}", "package.json": '{"name":"x"}'},
        name="refresh-failed",
    )
    result = runner.invoke(
        cli_mod.app, ["scan", "--refresh-coverage", str(repo)],
    )
    assert result.exit_code == 0, f"scan failed: {result.output}"
    json_files = list((repo / "docs" / "state-reports").glob("*.json"))
    assert json_files, "JSON sidecar not written"
    data = json.loads(json_files[0].read_text())
    rule_ids = [f["rule_id"] for f in data["findings"]]
    evidence_types = [f["evidence_type"] for f in data["findings"]]
    assert "coverage_unavailable" in rule_ids, (
        f"sub-step D must KEEP coverage_unavailable; got rule_ids={rule_ids}"
    )
    assert "coverage_refresh_failed" in rule_ids, (
        f"sub-step D must APPEND coverage_refresh_failed; got rule_ids={rule_ids}"
    )
    assert "failed" in evidence_types, (
        f"sub-step D must emit at least one evidence_type='failed'; got {evidence_types}"
    )


# --- Plan 03-05 SC-3 contract: missing tools degrade gracefully ----------


def test_scan_emits_adapter_unavailable_rows_for_missing_tools(
    fake_repo, runner
):
    """SC-3: a TS-like repo with no node_modules/.bin → scan completes
    + ledger surfaces typescript-node:* unavailable rows.

    Does NOT use the integration marker (mock-free; relies on the live
    adapter's graceful degradation when ``resolve_tool`` exhausts the
    project-local + PATH walk).
    """
    import json
    from repo_audit.cli import app

    repo = fake_repo(
        {
            "package.json": '{"name":"x","type":"module"}',
            "tsconfig.json": "{}",
            "eslint.config.js": "export default [];\n",
        },
        name="missing-tools",
    )
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0, f"scan failed: {result.output}"
    json_files = list((repo / "docs" / "state-reports").glob("*.json"))
    assert json_files, "JSON sidecar not written"
    data = json.loads(json_files[0].read_text())
    unavail_collectors = [
        u["collector"] for u in data["scope_ledger"]["unavailable"]
    ]
    assert any("typescript-node:" in c for c in unavail_collectors), (
        f"Expected typescript-node:* unavailable rows in scope ledger; "
        f"got: {unavail_collectors}"
    )
