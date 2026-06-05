"""Call-time ``.repo-audit.yaml`` ``fuzz:`` reader (Phase 16, FUZZ-01).

``read_fuzz_config(repo_path)`` loads the per-repo ``fuzz:`` block at CALL time
(the ``quality_depth/config.py::read_quality_depth_config`` precedent), layering
it over the documented adapter defaults. This honors per-repo overrides without
touching any shipped descriptor.

Security (mirrors T-15-01 / T-15-02): the file is loaded ONLY via
``ruamel.yaml.YAML(typ='safe')`` — the safe loader refuses ``!!python/object`` /
``!!python/name`` so a poisoned repo YAML cannot execute Python at load. PyYAML
is NEVER imported (CLAUDE.md mandate). A missing file, a missing block, an
unknown key, or a malformed YAML → all defaults (the read NEVER raises; a
hostile/broken user YAML must not break a scan).

Config surface (D-16-05):

  * ``budget_seconds``  per-native-target wall-clock cap (default ~90s). This is
    the AUTHORITATIVE bound enforced via ``run_tool(timeout_seconds=...)`` — NOT
    the fuzz engine's own ``-max_total_time`` flag (Pitfall 3). A native fuzzer
    runs until killed, so the run_tool wall-clock cap is the only honest bound.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

# Documented adapter default. config overrides layer on top at call time.
# D-16-05: a per-native-target wall-clock budget (this is `_run_mutation_tier`
# re-shaped with a 60-120s cap instead of 1800s).
_DEFAULT_BUDGET_SECONDS: int = 90


class FuzzConfig(BaseModel):
    """Resolved fuzz config (defaults + per-repo override layered).

    Frozen + ``extra='forbid'``: an unexpected key in the user's ``fuzz:`` block
    is dropped before construction (see :func:`read_fuzz_config`), so the model
    only ever sees the known surface; the frozen flag makes the resolved config
    immutable for the scan.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    budget_seconds: int = Field(default=_DEFAULT_BUDGET_SECONDS)


# The known override keys — anything else in the user's block is ignored (so an
# unrelated future key cannot trip extra='forbid' and break the scan).
_KNOWN_KEYS: frozenset[str] = frozenset(FuzzConfig.model_fields)


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``fuzz`` block.

    Read at CALL time via ``ruamel.yaml.YAML(typ='safe')`` (the safe loader
    refuses ``!!python/*`` tags). Returns an empty dict when the file is absent /
    unreadable / has no ``fuzz`` block, so the documented defaults stand. NEVER
    raises (a poisoned or malformed user YAML must not break a scan).
    """
    override_file = Path(repo_path) / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        block = doc.get("fuzz") or {}
        return block if isinstance(block, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def read_fuzz_config(repo_path: Path) -> FuzzConfig:
    """Read the repo's ``fuzz`` config, layering it over the defaults.

    Args:
        repo_path: the target repository root. Its ``.repo-audit.yaml`` is
            read at call time; absent file / block → all documented defaults.

    Returns:
        A frozen :class:`FuzzConfig`. Never raises: a missing file, a missing
        block, an unknown override key, or a malformed YAML all degrade to the
        documented defaults.
    """
    override = _load_repo_override(Path(repo_path))
    # Only pass through known keys; drop unrecognized ones so a future/unrelated
    # key in the user's block cannot trip extra='forbid'.
    kwargs = {k: v for k, v in override.items() if k in _KNOWN_KEYS and v is not None}
    try:
        return FuzzConfig(**kwargs)
    except Exception:  # noqa: BLE001 — a bad value type never breaks a scan
        return FuzzConfig()


__all__ = ["FuzzConfig", "read_fuzz_config", "_DEFAULT_BUDGET_SECONDS"]
