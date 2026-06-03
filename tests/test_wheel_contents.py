"""Load-bearing wheel-contents tripwire (SC-5 / CRIT-7 / threat T-06-07).

The standard Repo Audit build MUST stay license-clean: it ships NO CodeQL
binary and NO redistributed Semgrep rule pack. CodeQL and commercial scanners
arrive only as default-OFF, opt-in adapters (Phase 16) that the operator enables
with a use-rights attestation — those adapters resolve tools from the host / PATH
and never bundle proprietary binaries or rule YAML into our wheel.

This test is the enforcement of that contract. It builds the wheel fresh (so it
reflects HEAD, not a stale ``dist/``) and inspects the archive namelist. It MUST
stay green. If a future vendoring or dependency change drags a CodeQL binary or a
Semgrep ruleset into the package tree, this test fails loudly and the build is
caught before distribution.

The assertions are deliberately specific so they do not false-positive on the
project's own legitimate artifacts:

  * our own ``adapter.yaml`` / ``faithfulness.yaml`` config files, and
  * the vendored ``scc`` binary tree (``vendor/scc/...``, including ``LICENSE-scc.txt``).
"""

from __future__ import annotations

import glob
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _build_wheel(out_dir: Path) -> Path:
    """Build the project wheel into ``out_dir`` and return the .whl path."""
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(out_dir)],
        cwd=str(PROJECT_ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = glob.glob(str(out_dir / "*.whl"))
    assert wheels, f"uv build produced no wheel in {out_dir}"
    return Path(wheels[0])


@pytest.fixture(scope="module")
def wheel_namelist(tmp_path_factory) -> list[str]:
    """Build the wheel fresh and return its entry names.

    Skips (rather than fails) when ``uv`` is unavailable so the suite still runs
    in a minimal environment without the build toolchain.
    """
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH — cannot build wheel for contents assertion")

    out_dir = tmp_path_factory.mktemp("wheel_build")
    wheel = _build_wheel(out_dir)
    with zipfile.ZipFile(wheel) as zf:
        return zf.namelist()


def test_wheel_ships_no_codeql_binary(wheel_namelist: list[str]):
    """No wheel entry references CodeQL (CRIT-7).

    A case-insensitive ``codeql`` substring catches both a bundled ``codeql`` /
    ``codeql.exe`` executable and any CodeQL query pack or support file.
    """
    offenders = [name for name in wheel_namelist if "codeql" in name.lower()]
    assert not offenders, (
        "Wheel must ship NO CodeQL artifact (CRIT-7). CodeQL is a default-OFF, "
        "opt-in, host-resolved adapter (Phase 16) and must never be bundled. "
        f"Offending entries: {offenders}"
    )


def test_wheel_ships_no_semgrep_rule_yaml(wheel_namelist: list[str]):
    """No wheel entry is a redistributed Semgrep rule pack (CRIT-7).

    A Semgrep ruleset is a YAML/YML file whose path is associated with Semgrep.
    We flag any entry whose path contains ``semgrep`` AND ends in ``.yml`` /
    ``.yaml``. This is specific enough not to trip on the project's own
    ``adapter.yaml`` / ``faithfulness.yaml`` (neither contains ``semgrep`` in its
    path), while still catching a vendored ``semgrep/rules/*.yaml`` pack.
    """
    offenders = [
        name
        for name in wheel_namelist
        if "semgrep" in name.lower() and name.lower().endswith((".yml", ".yaml"))
    ]
    assert not offenders, (
        "Wheel must ship NO redistributed Semgrep rule YAML (CRIT-7). Semgrep "
        "rules are proprietary/licensed and arrive only via opt-in adapters that "
        "do not bundle them. "
        f"Offending entries: {offenders}"
    )


def test_wheel_ships_no_semgrep_artifact_at_all(wheel_namelist: list[str]):
    """Belt-and-suspenders: no BUNDLED Semgrep artifact in the wheel (CRIT-7).

    Catches a bundled Semgrep binary or support file even if it is not a YAML
    rule pack. The project ships no third-party Semgrep artifacts in the standard
    build — Semgrep is invoked only as a host/PATH-resolved subprocess.

    Our OWN ``.py`` source under ``repo_audit/adapters/sast/`` (e.g.
    ``semgrep.py``, the collector that SHELLS OUT to host-resolved Semgrep) is
    NOT a bundled Semgrep artifact — it is our Apache-licensed source code and
    bundles nothing proprietary. The test docstring's "do not false-positive on
    the project's own legitimate artifacts" contract (Plan 10-03) requires
    excluding it; a vendored Semgrep binary/pack would land under ``vendor/`` or
    as a non-``.py`` data file and is still caught.
    """
    offenders = [
        name
        for name in wheel_namelist
        if "semgrep" in name.lower()
        and not (
            name.startswith("repo_audit/") and name.lower().endswith(".py")
        )
    ]
    assert not offenders, (
        "Wheel must ship NO bundled Semgrep artifact (CRIT-7). "
        f"Offending entries: {offenders}"
    )


def test_wheel_ships_osv_and_grype_binaries(wheel_namelist: list[str]):
    """The standard build SHIPS the vendored osv-scanner + grype binaries (SCA-01/02).

    These are the Phase-7 vulnerability scanners, vendored at the flat
    ``vendor/<tool>/<tool>`` layout ``resolve_tool`` reads (D-07-09). They are
    Apache-2.0 (license text ships alongside each), so — unlike CodeQL / Semgrep —
    they are fine to redistribute in the standard wheel. This positive assertion
    guards against a packaging change silently dropping them: without the binaries
    in the wheel, an installed ``arch`` falls back to PATH/unavailable for SCA.
    """
    assert any(
        n.endswith("vendor/osv-scanner/osv-scanner") for n in wheel_namelist
    ), "osv-scanner binary missing from wheel"
    assert any(
        n.endswith("vendor/grype/grype") for n in wheel_namelist
    ), "grype binary missing from wheel"


def test_wheel_ships_syft_binary(wheel_namelist: list[str]):
    """The standard build SHIPS the vendored Syft binary + LICENSE (SUP-02).

    Syft is the Phase-12 SBOM generator, vendored at the same flat
    ``vendor/<tool>/<tool>`` layout ``resolve_tool`` reads (mirrors the Phase-7
    osv-scanner / grype precedent). It is Apache-2.0 (the release LICENSE ships
    alongside), so — unlike CodeQL / Semgrep — it is fine to redistribute in the
    standard wheel. This positive assertion guards against a packaging change
    silently dropping it: without the binary in the wheel, an installed ``arch``
    falls back to PATH/unavailable for SBOM generation.
    """
    assert any(
        n.endswith("vendor/syft/syft") for n in wheel_namelist
    ), "syft binary missing from wheel"
    assert any(
        n.endswith("vendor/syft/LICENSE") for n in wheel_namelist
    ), "syft LICENSE missing from wheel"
