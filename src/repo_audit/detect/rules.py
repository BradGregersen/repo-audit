"""Manifest-file detection rule table.

Each StackRule maps a small set of filename patterns to a stack name.
Priority is encoded via `overrides`: when Expo matches, it suppresses
typescript-node and react-native in the SAME directory (since an Expo
app also has package.json + tsconfig.json + the React Native pieces).
Supabase has NO overrides — it composes onto whatever app stack exists.

The table is a Python module (not YAML) for type safety, IDE navigability,
and to avoid pulling in ruamel.yaml until Phase 7 actually needs it for
user config (CLAUDE.md anti-pattern: no PyYAML; ruamel.yaml deferred).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StackRule:
    """A single stack-detection rule.

    - requires_all: every pattern must be present in the same directory
    - requires_any: at least one pattern must be present
    - boosts_if_any: optional patterns that raise the confidence score
    - overrides: when this rule matches, suppress these stack names in the SAME dir
    - base_confidence: starting confidence (boosts add 0.05 per match, capped at 1.0)

    Patterns are matched as exact filenames OR as fnmatch globs (when they
    contain `*` or `?`). Subpath patterns (containing `/`) are matched against
    the directory's full set of relative paths.
    """

    name: str
    requires_all: tuple[str, ...] = ()
    requires_any: tuple[str, ...] = ()
    boosts_if_any: tuple[str, ...] = ()
    overrides: tuple[str, ...] = ()
    base_confidence: float = 0.8


# Order matters for documentation only — override resolution is symmetric.
MANIFEST_RULES: tuple[StackRule, ...] = (
    # Expo: package.json + app.json (or app.config.{js,ts}) — overrides plain TS + RN.
    StackRule(
        name="expo",
        requires_all=("package.json",),
        requires_any=("app.json", "app.config.js", "app.config.ts"),
        boosts_if_any=("ios/Podfile", "android/build.gradle"),
        overrides=("typescript-node", "react-native"),
        base_confidence=0.9,
    ),
    # React Native (non-Expo): package.json + iOS/Android shell or metro config.
    StackRule(
        name="react-native",
        requires_all=("package.json",),
        requires_any=("ios/Podfile", "android/build.gradle", "metro.config.js"),
        overrides=("typescript-node",),
        base_confidence=0.85,
    ),
    # TypeScript / Node: tsconfig.json (preferred) or package.json+typescript dep.
    StackRule(
        name="typescript-node",
        requires_any=("tsconfig.json", "tsconfig.base.json"),
        boosts_if_any=("package.json",),
        base_confidence=0.8,
    ),
    # Kotlin/Android (or plain Kotlin/Gradle): build.gradle.kts or build.gradle.
    StackRule(
        name="kotlin-android",
        requires_any=("build.gradle.kts", "build.gradle"),
        boosts_if_any=("settings.gradle.kts", "settings.gradle", "AndroidManifest.xml"),
        base_confidence=0.85,
    ),
    # Python: pyproject.toml or setup.py/setup.cfg/requirements.txt.
    StackRule(
        name="python",
        requires_any=("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"),
        base_confidence=0.85,
    ),
    # Rust: Cargo.toml is unambiguous.
    StackRule(
        name="rust",
        requires_any=("Cargo.toml",),
        base_confidence=0.95,
    ),
    # Go: go.mod is unambiguous.
    StackRule(
        name="go",
        requires_any=("go.mod",),
        base_confidence=0.95,
    ),
    # C#/.NET: *.csproj or *.sln (glob patterns).
    StackRule(
        name="csharp-dotnet",
        requires_any=("*.csproj", "*.sln"),
        base_confidence=0.9,
    ),
    # C++: CMakeLists.txt or Makefile (latter is ambiguous, so lower base confidence).
    StackRule(
        name="cpp",
        requires_any=("CMakeLists.txt", "Makefile"),
        boosts_if_any=("conanfile.txt", "conanfile.py", "vcpkg.json"),
        base_confidence=0.6,
    ),
    # Supabase: composes onto any app stack (no overrides).
    StackRule(
        name="supabase",
        requires_any=("supabase/config.toml",),
        base_confidence=0.95,
    ),
)
