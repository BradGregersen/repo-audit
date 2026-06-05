"""Call-time ``.repo-audit.yaml`` ``e2e:`` block reader (Plan 16-02).

``read_e2e_config(repo_path)`` loads the per-repo ``e2e:`` block at CALL time
(modeled VERBATIM on ``quality_depth/config.py``), layering it over the
documented defaults. This honors per-repo overrides without touching the shipped
adapter descriptor.

Security (T-16-02-02 spirit / CLAUDE.md mandate): the file is loaded ONLY via
``ruamel.yaml.YAML(typ='safe')`` — the safe loader refuses ``!!python/object`` /
``!!python/name`` so a poisoned repo YAML cannot execute Python at load. The
unsafe full-loader library is NEVER imported (CLAUDE.md mandate; only
``ruamel.yaml`` is used). A missing file, a missing block, an unknown override key, or a
malformed YAML → all defaults (the read NEVER raises; a hostile/broken user YAML
must not break a scan).

Config surface:

  * ``coverage``        best-effort coverage toggle (D-16-03). True → the run step
                        attempts to read an already-emitted V8 coverage artifact;
                        it NEVER instruments the repo regardless of this flag.
  * ``timeout_seconds`` hard wall-clock bound for an opt-in harness run (the
                        ``run_tool`` SIGTERM→5s→SIGKILL cap; default 600s — E2E is
                        the deepest, slowest lane).
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

# Documented adapter defaults. config overrides layer on top at call time.
_DEFAULT_COVERAGE: bool = True
_DEFAULT_TIMEOUT_SECONDS: int = 600


class E2eConfig(BaseModel):
    """Resolved E2E config (defaults + per-repo override layered).

    Frozen + ``extra="forbid"``: an unexpected key in the user's ``e2e:`` block
    is dropped before construction (see :func:`read_e2e_config`), so the model
    only ever sees the known surface; the frozen flag makes the resolved config
    immutable for the scan.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    coverage: bool = Field(default=_DEFAULT_COVERAGE)
    timeout_seconds: int = Field(default=_DEFAULT_TIMEOUT_SECONDS)


# The known override keys — anything else in the user's block is ignored (so an
# unrelated future key cannot trip extra="forbid" and break the scan).
_KNOWN_KEYS: frozenset[str] = frozenset(E2eConfig.model_fields)


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``e2e`` block.

    Read at CALL time via ``ruamel.yaml.YAML(typ='safe')``. Returns an empty
    dict when the file is absent / unreadable / has no ``e2e`` block, so the
    documented defaults stand. NEVER raises (a poisoned or malformed user YAML
    must not break a scan).
    """
    override_file = Path(repo_path) / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        block = doc.get("e2e") or {}
        return block if isinstance(block, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def read_e2e_config(repo_path: Path) -> E2eConfig:
    """Read the repo's ``e2e`` config, layering it over the defaults.

    Args:
        repo_path: the target repository root. Its ``.repo-audit.yaml`` is
            read at call time; absent file / block → all documented defaults.

    Returns:
        A frozen :class:`E2eConfig`. Never raises: a missing file, a missing
        block, an unknown override key, or a malformed YAML all degrade to the
        documented defaults.
    """
    override = _load_repo_override(Path(repo_path))
    # Only pass through known keys; drop unrecognized ones so a future/unrelated
    # key in the user's block cannot trip extra="forbid".
    kwargs = {k: v for k, v in override.items() if k in _KNOWN_KEYS and v is not None}
    try:
        return E2eConfig(**kwargs)
    except Exception:  # noqa: BLE001 — a bad value type never breaks a scan
        return E2eConfig()


__all__ = ["E2eConfig", "read_e2e_config"]
