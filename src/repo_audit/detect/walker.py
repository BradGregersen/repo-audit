"""Walk a repo and collect manifest filenames + glob-pattern paths per directory.

Walker discipline (read-only contract, performance):
- Bounded depth (default 4) to avoid pathological globs
- Default-excludes the cache/build/dependency directories that dominate
  walk time on every real-world repo (per PITFALLS.md m1, M11)
- Reads filenames only; never reads file contents
- Never writes anywhere
"""
from __future__ import annotations

from pathlib import Path

# Directories we never walk into. Conservative — only the universal cases that
# will appear in every stack. Per-stack tuning lands in Phase 3+ adapters.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "target", ".next", ".gradle", "coverage", "vendor",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    ".tox", ".idea", ".vscode",
})


def walk_for_manifests(
    repo_path: Path,
    *,
    max_depth: int = 4,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> dict[Path, set[str]]:
    """Return {directory_path: {filenames_present_in_that_directory}}.

    Includes a special key for "directory contains subpath X" — for rules
    that need to match e.g. `ios/Podfile` or `supabase/config.toml`, those
    paths are added to the parent directory's set with a leading subpath
    prefix (e.g. "ios/Podfile", "supabase/config.toml").
    """
    repo_path = repo_path.resolve()
    result: dict[Path, set[str]] = {}

    def _walk(dir_path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(dir_path.iterdir())
        except (PermissionError, OSError):
            return
        files: set[str] = set()
        subdirs: list[Path] = []
        for e in entries:
            if e.is_dir():
                if e.name in skip_dirs:
                    continue
                subdirs.append(e)
            elif e.is_file():
                files.add(e.name)
        # Add subpath markers for files that live one level down inside a
        # named subdir (e.g. ios/Podfile, supabase/config.toml, android/build.gradle).
        for sub in subdirs:
            try:
                for child in sub.iterdir():
                    if child.is_file():
                        files.add(f"{sub.name}/{child.name}")
            except (PermissionError, OSError):
                pass
        if files:
            result[dir_path] = files
        for sub in subdirs:
            _walk(sub, depth + 1)

    _walk(repo_path, depth=0)
    return result
