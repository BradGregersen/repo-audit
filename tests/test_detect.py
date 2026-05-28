"""Detector tests. Implementation lands in Plan 03 (Wave 1)."""
import pytest

pytestmark = pytest.mark.xfail(strict=False, reason="Plan 03 implements detector")


def test_detect_polyglot_repo(polyglot_repo):
    """SC-2 / DETECT-01 — typescript-node + supabase both detected, with root_dirs."""
    from repo_audit.detect.detector import detect_stacks
    result = detect_stacks(polyglot_repo)
    stack_names = {s.stack for s in result.stacks}
    assert "typescript-node" in stack_names
    assert "supabase" in stack_names


def test_detect_expo_overrides_react_native_and_typescript(expo_supabase_repo):
    """DETECT-01 — Expo overrides typescript-node + react-native in same dir; supabase composes."""
    from repo_audit.detect.detector import detect_stacks
    result = detect_stacks(expo_supabase_repo)
    stack_names = {s.stack for s in result.stacks}
    assert "expo" in stack_names
    assert "supabase" in stack_names
    # Expo's overrides=("typescript-node", "react-native") removes them from the result
    assert "typescript-node" not in stack_names


def test_detect_no_manifests_returns_empty(empty_repo):
    """SC-2-edge / DETECT-03 — repo with no manifests returns DetectionResult(stacks=[])."""
    from repo_audit.detect.detector import detect_stacks
    result = detect_stacks(empty_repo)
    assert result.stacks == []


def test_detect_multi_root_python_and_typescript(fake_repo):
    """DETECT-02 — monorepo with TS at /web/ and Python at /scripts/ returns 2 records with distinct root_dirs."""
    from repo_audit.detect.detector import detect_stacks
    repo = fake_repo({
        "web/package.json": '{}',
        "web/tsconfig.json": '{}',
        "scripts/pyproject.toml": '[project]\nname="x"\nversion="0"\n',
    }, name="mono")
    result = detect_stacks(repo)
    stack_names = {s.stack for s in result.stacks}
    root_dirs = {str(s.root_dir.relative_to(repo)) for s in result.stacks}
    assert "typescript-node" in stack_names
    assert "python" in stack_names
    assert "web" in root_dirs
    assert "scripts" in root_dirs


@pytest.mark.parametrize("manifest,expected_stack", [
    ({"Cargo.toml": '[package]\nname="x"\nversion="0.1"\n'}, "rust"),
    ({"go.mod": "module x\ngo 1.22\n"}, "go"),
    ({"CMakeLists.txt": "cmake_minimum_required(VERSION 3.10)\n"}, "cpp"),
    ({"build.gradle.kts": "plugins {}\n"}, "kotlin-android"),
    ({"x.csproj": "<Project />"}, "csharp-dotnet"),
])
def test_detect_single_stack_manifests(fake_repo, manifest, expected_stack):
    """DETECT-01 — each individual stack manifest detected."""
    from repo_audit.detect.detector import detect_stacks
    repo = fake_repo(manifest, name=f"single-{expected_stack}")
    result = detect_stacks(repo)
    assert expected_stack in {s.stack for s in result.stacks}
