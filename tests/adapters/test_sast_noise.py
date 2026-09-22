"""SAST-02 — noise floor (path-exclude + severity-floor, overridable) (Plan 10-02).

Laid down in Wave 0 (Plan 10-00) as a RED-then-GREEN target. The opening
``pytest.importorskip`` keeps this module SKIPPED until the Wave-2 implementation
``repo_audit.adapters.sast.noise`` lands. Assertions are REAL (never
``pass``) so the module fails RED the instant the import resolves.

CRIT-2: the noise floor runs BEFORE any finding reaches the report, and is
overridable via an ``.repo-audit.yaml``-shaped ``sast`` override.
"""
from __future__ import annotations

import pytest

noise = pytest.importorskip(
    "repo_audit.adapters.sast.noise",
    reason="optional module repo_audit.adapters.sast.noise not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.schema.finding import Evidence, Finding


def _finding(*, file: str, severity: str) -> Finding:
    """Build a minimal valid static/candidate security Finding for floor tests."""
    return Finding(
        dimension="security",
        severity=severity,  # type: ignore[arg-type]
        file=file,
        line=1,
        evidence=Evidence(
            tool="semgrep",
            output_snippet=f"finding in {file}",
            parsed_value={"rule_id": "test.rule"},
        ),
        evidence_type="static",
        confidence="candidate",
        source_tool="semgrep",
        rule_id="test.rule",
    )


def _fixture_findings() -> list[Finding]:
    return [
        _finding(file="src/app.ts", severity="major"),          # kept
        _finding(file="__tests__/app.test.ts", severity="major"),  # test path -> dropped
        _finding(file="node_modules/lib/index.js", severity="major"),  # vendored -> dropped
        _finding(file="src/generated/api.ts", severity="major"),  # generated -> dropped
        _finding(file="src/util.ts", severity="info"),          # sub-floor -> dropped
        _finding(file="src/core.ts", severity="minor"),         # at/above floor -> kept
    ]


def test_path_excludes_and_floor():
    """Test/vendored/generated-path AND sub-floor-severity findings are dropped.

    Deterministic (CRIT-2 "before any finding reaches the report").
    """
    findings = _fixture_findings()
    kept = noise.apply_noise_floor(findings)
    kept_files = {f.file for f in kept}

    # Path excludes drop test/vendored/generated.
    assert "__tests__/app.test.ts" not in kept_files
    assert "node_modules/lib/index.js" not in kept_files
    assert "src/generated/api.ts" not in kept_files
    # Severity floor drops info; keeps the major in non-excluded path.
    assert "src/util.ts" not in kept_files
    assert "src/app.ts" in kept_files
    # Determinism: re-running yields the same kept set.
    assert {f.file for f in noise.apply_noise_floor(findings)} == kept_files


def test_override():
    """An .repo-audit.yaml-shaped sast override changes the kept set (CRIT-2)."""
    findings = _fixture_findings()
    baseline = {f.file for f in noise.apply_noise_floor(findings)}

    # Raise the floor to 'major' (drops the kept 'minor') AND add 'src/core.ts'
    # to excludes — both must change the kept set, proving overridability.
    override = {
        "severity_floor": "major",
        "exclude_paths": ["src/core.ts"],
    }
    overridden = {f.file for f in noise.apply_noise_floor(findings, override=override)}

    assert overridden != baseline
    assert "src/core.ts" not in overridden
