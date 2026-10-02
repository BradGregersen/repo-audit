"""ARCH-01 circular-dependency collector contract (Plan 14-02, Wave-1).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-1
implementation ``repo_audit.adapters.architecture.circular``
(dependency-cruiser) lands, at which point these contract assertions activate
automatically. The function NAMES match the 14-RESEARCH Test Map
(``test_*_config`` / ``test_*_unavailable`` / ``test_*_absent``) and must NOT be
renamed.

dependency-cruiser emits JSON (``--output-type json`` to stdout — NOT a SARIF
reporter, which does not exist; D-14-04 / Pitfall 1) and one Finding is built
per ``summary.violations[]`` (depcruise_json.py). When the repo brings its own
``.dependency-cruiser.*`` config, the collector passes NO ``--config`` (auto
discovery); a zero-config repo gets a shipped minimal ruleset via
``--config <tempfile>`` (Pitfall 5).

run_tool is stubbed so the parse path runs hermetically regardless of whether
dependency-cruiser is installed on the test host.
"""
from __future__ import annotations

import re

import pytest

circular = pytest.importorskip(
    "repo_audit.adapters.architecture.circular",
    reason="optional module repo_audit.adapters.architecture.circular not importable — feature not present in this build, or the install is incomplete",
)

_FAKE_BIN = "/usr/bin/__depcruise__"


def _stub_resolve(monkeypatch, binary=_FAKE_BIN):
    monkeypatch.setattr(
        circular, "resolve_tool", lambda *a, **k: binary, raising=False
    )


def _stub_run_returns_json(monkeypatch, json_text, *, returncode=0):
    """Stub run_tool so depcruise 'emits' the recorded JSON on stdout."""
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        return toolops.InvocationResult(
            stdout=json_text, stderr="", returncode=returncode
        )

    monkeypatch.setattr(circular, "run_tool", _run, raising=False)


def test_one_finding_per_violation(monkeypatch, fake_js_repo, load_json) -> None:
    """summary.violations[] → one Finding each, citing from/to/cycle."""
    import json

    doc = load_json("dependency-cruiser")
    repo = fake_js_repo(circular=True, with_config=True)
    _stub_resolve(monkeypatch)
    _stub_run_returns_json(monkeypatch, json.dumps(doc))

    result = circular.collect_dependency_cruiser(repo, {})

    assert len(result.findings) == len(doc["summary"]["violations"])
    f = result.findings[0]
    assert f.rule_id == "no-circular"
    assert f.file == "src/a.js"
    assert f.dimension == "architecture_rot"
    assert f.evidence_type == "static"
    assert f.confidence == "candidate"


def test_repo_with_config_passes_no_config_flag(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """A repo with its own .dependency-cruiser.* → NO shipped --config."""
    import json

    captured: dict = {}
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        captured["argv"] = list(argv)
        return toolops.InvocationResult(
            stdout=json.dumps(load_json("dependency-cruiser")),
            stderr="",
            returncode=0,
        )

    repo = fake_js_repo(circular=True, with_config=True)
    _stub_resolve(monkeypatch)
    monkeypatch.setattr(circular, "run_tool", _run, raising=False)

    circular.collect_dependency_cruiser(repo, {})

    assert "--config" not in captured["argv"]


def test_zero_config_repo_ships_minimal_config(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """A zero-config repo → shipped minimal ruleset via --config <tempfile>."""
    import json

    captured: dict = {}
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        captured["argv"] = list(argv)
        return toolops.InvocationResult(
            stdout=json.dumps(load_json("dependency-cruiser")),
            stderr="",
            returncode=0,
        )

    repo = fake_js_repo(circular=True, with_config=False)
    _stub_resolve(monkeypatch)
    monkeypatch.setattr(circular, "run_tool", _run, raising=False)

    circular.collect_dependency_cruiser(repo, {})

    assert "--config" in captured["argv"]


def test_non_js_stack_not_invoked_unavailable(monkeypatch, fake_js_repo) -> None:
    """A non-JS-stack repo → unavailable/not_applicable, tool NEVER invoked."""
    invoked = {"n": 0}
    from repo_audit.adapters import toolops

    def _run(*a, **k):
        invoked["n"] += 1
        return toolops.InvocationResult(stdout="", stderr="", returncode=0)

    repo = fake_js_repo(circular=False, package_json=False)
    _stub_resolve(monkeypatch)
    monkeypatch.setattr(circular, "run_tool", _run, raising=False)

    result = circular.collect_dependency_cruiser(repo, {}, stacks=[])

    assert result.status in {"unavailable", "not_applicable"}
    assert invoked["n"] == 0


def test_depcruise_absent_unavailable(monkeypatch, fake_js_repo) -> None:
    """resolve_tool miss → unavailable, never raises."""
    repo = fake_js_repo(circular=True)
    monkeypatch.setattr(
        circular, "resolve_tool", lambda *a, **k: None, raising=False
    )

    result = circular.collect_dependency_cruiser(repo, {})

    assert result.status == "unavailable"
    assert result.findings == []


def _capture_run(monkeypatch, stdout: str, captured: dict) -> None:
    """Stub run_tool to record the argv and the shipped config it was given."""
    import json

    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        captured["argv"] = list(argv)
        if "--config" in argv:
            config_path = argv[argv.index("--config") + 1]
            with open(config_path, encoding="utf-8") as fh:
                captured["config"] = json.load(fh)
        return toolops.InvocationResult(stdout=stdout, stderr="", returncode=0)

    monkeypatch.setattr(circular, "run_tool", _run, raising=False)


def test_source_root_is_src_when_present(monkeypatch, fake_js_repo, load_json) -> None:
    """A repo with ``src/`` is cruised from ``src``."""
    import json

    captured: dict = {}
    repo = fake_js_repo(circular=True)
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    assert captured["argv"][-1] == "src"


def test_source_roots_are_the_source_dirs_present(monkeypatch, tmp_path, load_json) -> None:
    """An Expo or React Native app keeps its code in ``app/`` and ``lib/``, not ``src/``.

    Cruising a missing ``src`` made dependency-cruiser exit with no JSON at all, and
    cruising ``.`` reaches stray files (templates, scratch) that abort the run.
    """
    import json

    repo = tmp_path / "expo_app"
    for d in ("app", "lib", "docs"):
        (repo / d).mkdir(parents=True)
    (repo / "package.json").write_text('{"name": "expo-app"}\n', encoding="utf-8")
    captured: dict = {}
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    assert captured["argv"][-2:] == ["app", "lib"]


def test_source_root_falls_back_to_repo_root(monkeypatch, tmp_path, load_json) -> None:
    """A repo with none of the usual source dirs is cruised from its root."""
    import json

    repo = tmp_path / "flat_repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "flat"}\n', encoding="utf-8")
    (repo / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    captured: dict = {}
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    assert captured["argv"][-1] == "."


def test_shipped_config_stays_out_of_node_modules_and_reads_tsconfig(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """The zero-config ruleset never follows node_modules and resolves tsconfig path aliases."""
    import json

    captured: dict = {}
    repo = fake_js_repo(circular=True)
    (repo / "tsconfig.json").write_text('{"compilerOptions": {}}\n', encoding="utf-8")
    (repo / "node_modules").mkdir()
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    options = captured["config"]["options"]
    assert options["doNotFollow"]["path"] == "node_modules"
    assert "node_modules" in options["exclude"]["path"]
    assert re.search(options["exclude"]["path"], ".planning/x/TEMPLATE.test.tsx")
    assert not re.search(options["exclude"]["path"], "app/index.tsx")
    assert options["tsPreCompilationDeps"] is True
    assert options["tsConfig"] == {"fileName": "tsconfig.json"}
    assert [r["name"] for r in captured["config"]["forbidden"]] == [
        "no-circular",
        "not-to-unresolvable",
        "not-to-dev-dep",
    ]


def test_shipped_config_omits_tsconfig_when_the_repo_has_none(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """A plain JavaScript repo gets no tsConfig option (depcruise would fail to open it)."""
    import json

    captured: dict = {}
    repo = fake_js_repo(circular=True)
    (repo / "node_modules").mkdir()
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    assert "tsConfig" not in captured["config"]["options"]


def test_shipped_config_omits_tsconfig_without_installed_dependencies(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """A tsconfig usually extends a package (``astro/tsconfigs/strict``); without
    node_modules depcruise cannot load it and exits with no JSON at all."""
    import json

    captured: dict = {}
    repo = fake_js_repo(circular=True)
    (repo / "tsconfig.json").write_text(
        '{"extends": "astro/tsconfigs/strict"}\n', encoding="utf-8"
    )
    _stub_resolve(monkeypatch)
    _capture_run(monkeypatch, json.dumps(load_json("dependency-cruiser")), captured)

    circular.collect_dependency_cruiser(repo, {})

    assert "tsConfig" not in captured["config"]["options"]


def test_zero_modules_cruised_is_unavailable(monkeypatch, fake_js_repo) -> None:
    """A cruise that read nothing is not a clean result.

    The global dependency-cruiser cannot parse TypeScript without a TypeScript it
    supports; it then returns an empty graph with zero violations, which used to
    read as ``ok``.
    """
    import json

    repo = fake_js_repo(circular=True)
    _stub_resolve(monkeypatch)
    _stub_run_returns_json(
        monkeypatch,
        json.dumps({"modules": [], "summary": {"violations": [], "totalCruised": 0}}),
    )

    result = circular.collect_dependency_cruiser(repo, {})

    assert result.status == "unavailable"
    assert "0 modules" in result.notes
