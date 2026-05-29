"""D-47 ESLint config-style detection.

ESLint 9.x ships with the new "flat" config format
(``eslint.config.{js,mjs,cjs,ts}``). Many projects still carry the
legacy ``.eslintrc.*`` format or its ``package.json``-embedded variant
(``"eslintConfig": {...}``). Some — typically mid-migration — carry
both at the repo root, in which case ESLint applies a documented
precedence (flat wins) but we surface the duality so the adapter can
warn rather than silently picking one.

Two public APIs are exported because the call sites have different
preferences:

    * ``detect_eslint_config_style(repo_path) -> 'flat' | 'legacy' | 'both' | 'none'``
      — the D-47 spec'd shape: always returns a Literal string. Useful
      when ``None`` is awkward (logging, JSON serialisation).

    * ``detect_eslint_config(repo_path) -> 'flat' | 'legacy' | 'both' | None``
      — the friendlier shape consumed by ``adapters/typescript/__init__.py``
      and the Wave 0b adapter tests: ``None`` (instead of ``'none'``)
      reads naturally at call sites that branch on absence.

Both helpers walk the SAME rule table — the wrapper just maps
``'none' -> None``. Do not duplicate the rule list.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

EslintConfigStyle = Literal["flat", "legacy", "both", "none"]

_FLAT_NAMES: tuple[str, ...] = (
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "eslint.config.ts",
)

_LEGACY_NAMES: tuple[str, ...] = (
    ".eslintrc.json",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.yaml",
    ".eslintrc.yml",
)


def detect_eslint_config_style(repo_path: Path) -> EslintConfigStyle:
    """Inspect ``repo_path`` for ESLint configuration files.

    Returns one of ``'flat' | 'legacy' | 'both' | 'none'``.

    Detection rules:
        * Flat: any of ``eslint.config.{js,mjs,cjs,ts}`` at the repo root.
        * Legacy: any of ``.eslintrc.{json,js,cjs,yaml,yml}`` at the repo
          root, OR ``package.json`` carries an ``eslintConfig`` key.
        * Both: flat and legacy each match independently.
        * None: nothing matched.

    Only the repo root is inspected — nested ESLint configs (per-package
    in a monorepo) are out of scope for this helper; the adapter walks
    each ``StackProfile.root_dir`` separately and calls this helper per
    root.
    """
    has_flat = any((repo_path / n).is_file() for n in _FLAT_NAMES)
    has_legacy = any((repo_path / n).is_file() for n in _LEGACY_NAMES)
    # ``package.json#eslintConfig`` is also a legacy form per the
    # ESLint 8 docs. Read defensively: malformed package.json is
    # common in real-world target repos and must not crash detection.
    if not has_legacy:
        pkg = repo_path / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                data = {}
            if isinstance(data, dict) and "eslintConfig" in data:
                has_legacy = True
    if has_flat and has_legacy:
        return "both"
    if has_flat:
        return "flat"
    if has_legacy:
        return "legacy"
    return "none"


def detect_eslint_config(repo_path: Path) -> Literal["flat", "legacy", "both"] | None:
    """Detect-eslint-config-style wrapper returning ``None`` instead of ``'none'``.

    Consumed by ``adapters/typescript/__init__.py`` and the Wave 0b
    adapter tests; the truthy/None shape reads cleanly at branch sites::

        cfg = detect_eslint_config(repo_path)
        if cfg is None:
            # adapter SKIPS eslint, emits unavailable
            ...
    """
    style = detect_eslint_config_style(repo_path)
    if style == "none":
        return None
    return style
