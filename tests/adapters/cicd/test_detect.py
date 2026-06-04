"""CI/CD surface detection-and-degrade matrix (Plan 13-01, Task 2).

The D-13-05 first-class degrade: ``detect.py`` must distinguish, read-only, which
of the three CI/CD surfaces (workflows / Dockerfile / IaC) a target repo has, so
each ``collect_*`` (Wave 1/2) can branch and emit an honest ``unavailable`` for an
absent surface. These tests pin that present×absent matrix plus the key edge
cases: ``node_modules`` exclusion, the conservative IaC trigger (a stray app
``*.yaml`` must NOT fire checkov), and the read-only guarantee (no subprocess, no
writes in the module source).

This file is intentionally self-contained (builds its own tmp repos) so it runs
green in Task 2 before the shared ``conftest.fake_cicd_repo`` factory lands in
Task 3.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.cicd import detect


def _write(path: Path, text: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------- #
# find_workflows
# --------------------------------------------------------------------------- #
def test_no_workflows_unavailable(tmp_path):
    """No .github/workflows dir -> find_workflows returns [] (the degrade sentinel)."""
    assert detect.find_workflows(tmp_path) == []
    surface = detect.detect_cicd_surface(tmp_path)
    assert surface.has_workflows is False


def test_workflows_present_sorted(tmp_path):
    """*.yml + *.yaml under .github/workflows -> sorted non-empty list."""
    _write(tmp_path / ".github" / "workflows" / "release.yaml")
    _write(tmp_path / ".github" / "workflows" / "ci.yml")
    found = detect.find_workflows(tmp_path)
    assert [p.name for p in found] == ["ci.yml", "release.yaml"]
    assert detect.detect_cicd_surface(tmp_path).has_workflows is True


def test_workflows_dir_must_be_under_dot_github(tmp_path):
    """A stray top-level workflows/ dir does NOT count (must be .github/workflows)."""
    _write(tmp_path / "workflows" / "ci.yml")
    assert detect.find_workflows(tmp_path) == []


# --------------------------------------------------------------------------- #
# find_dockerfiles
# --------------------------------------------------------------------------- #
def test_dockerfiles_variants_found(tmp_path):
    """Dockerfile, Dockerfile.prod, api.Dockerfile are all discovered."""
    _write(tmp_path / "Dockerfile")
    _write(tmp_path / "ops" / "Dockerfile.prod")
    _write(tmp_path / "services" / "api.Dockerfile")
    found = detect.find_dockerfiles(tmp_path)
    names = {p.name for p in found}
    assert names == {"Dockerfile", "Dockerfile.prod", "api.Dockerfile"}


def test_dockerfile_under_node_modules_excluded(tmp_path):
    """A Dockerfile under any node_modules parent is EXCLUDED."""
    _write(tmp_path / "Dockerfile")
    _write(tmp_path / "node_modules" / "somepkg" / "Dockerfile")
    found = detect.find_dockerfiles(tmp_path)
    assert all("node_modules" not in p.parts for p in found)
    assert [p.name for p in found] == ["Dockerfile"]


def test_no_dockerfile_unavailable(tmp_path):
    """No Dockerfile anywhere -> [] (the degrade sentinel)."""
    _write(tmp_path / "README.md")
    assert detect.find_dockerfiles(tmp_path) == []
    assert detect.detect_cicd_surface(tmp_path).has_dockerfiles is False


# --------------------------------------------------------------------------- #
# find_iac_config (conservative trigger)
# --------------------------------------------------------------------------- #
def test_iac_terraform_present(tmp_path):
    """A repo with main.tf -> non-empty IaC config."""
    _write(tmp_path / "infra" / "main.tf")
    found = detect.find_iac_config(tmp_path)
    assert [p.name for p in found] == ["main.tf"]
    assert detect.detect_cicd_surface(tmp_path).has_iac_config is True


def test_no_iac_unavailable(tmp_path):
    """A stray application *.yaml (no *.tf/Chart.yaml/kustomization/CFN) -> [] (conservative)."""
    _write(tmp_path / "config" / "app.yaml", "name: myapp\n")
    _write(tmp_path / "data" / "settings.yml", "k: v\n")
    assert detect.find_iac_config(tmp_path) == []
    assert detect.detect_cicd_surface(tmp_path).has_iac_config is False


def test_iac_conservative_markers(tmp_path):
    """Chart.yaml, kustomization.yaml, and CFN template markers all fire IaC."""
    _write(tmp_path / "chart" / "Chart.yaml")
    _write(tmp_path / "k8s" / "kustomization.yaml")
    _write(tmp_path / "cfn" / "stack.template.json", "{}\n")
    found = {p.name for p in detect.find_iac_config(tmp_path)}
    assert found == {"Chart.yaml", "kustomization.yaml", "stack.template.json"}


def test_iac_node_modules_excluded(tmp_path):
    """A *.tf under node_modules is EXCLUDED."""
    _write(tmp_path / "node_modules" / "pkg" / "vendored.tf")
    assert detect.find_iac_config(tmp_path) == []


# --------------------------------------------------------------------------- #
# detect_cicd_surface matrix
# --------------------------------------------------------------------------- #
def test_surface_all_absent(tmp_path):
    """Empty repo -> all three surfaces absent, any_surface False."""
    surface = detect.detect_cicd_surface(tmp_path)
    assert (surface.has_workflows, surface.has_dockerfiles, surface.has_iac_config) == (
        False,
        False,
        False,
    )
    assert surface.any_surface is False


def test_surface_all_present(tmp_path):
    """A repo with all three surfaces -> all present, any_surface True."""
    _write(tmp_path / ".github" / "workflows" / "ci.yml")
    _write(tmp_path / "Dockerfile")
    _write(tmp_path / "main.tf")
    surface = detect.detect_cicd_surface(tmp_path)
    assert (surface.has_workflows, surface.has_dockerfiles, surface.has_iac_config) == (
        True,
        True,
        True,
    )
    assert surface.any_surface is True


def test_surface_workflows_only_does_not_imply_others(tmp_path):
    """Workflows present, Dockerfile + IaC absent (the dominant fleet shape)."""
    _write(tmp_path / ".github" / "workflows" / "ci.yml")
    surface = detect.detect_cicd_surface(tmp_path)
    assert surface.has_workflows is True
    assert surface.has_dockerfiles is False
    assert surface.has_iac_config is False


# --------------------------------------------------------------------------- #
# read-only guarantee (T-13-01-PATH)
# --------------------------------------------------------------------------- #
def test_detect_module_is_read_only():
    """detect.py performs zero subprocess calls and zero filesystem writes.

    Greps the module SOURCE for the genuine write/exec patterns (not docstring
    prose): no ``import subprocess``, no ``write_text`` / ``write_bytes``, no
    write-mode ``open(...)``.
    """
    src = Path(detect.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "subprocess." not in src
    assert "write_text" not in src
    assert ".write_bytes" not in src
    # No write-mode file open.
    assert ', "w"' not in src and ", 'w'" not in src
    assert ".open(" not in src
