"""Call-time ``.repo-audit.yaml`` ``synthesis:`` reader (Phase 18, SYN-01).

``read_synthesis_config(repo_path)`` loads the per-repo ``synthesis:`` block at
CALL time (the ``dast/config.py`` precedent — D-16-10), layering it over the
documented synthesis defaults: ``top_n`` (the headline "what matters most" cap),
``epss_enabled`` (the opt-in EPSS network gate — default OFF), and
``epss_timeout_seconds`` (the wall-clock cap on the opt-in network fetch).

Security (T-18-04, mirrors T-16-05 / T-15-01): the file is loaded ONLY via
``ruamel.yaml.YAML(typ='safe')`` — the safe loader refuses ``!!python/object`` /
``!!python/name`` so a poisoned repo YAML cannot execute Python at load. The
unsafe full-YAML loader is NEVER imported (CLAUDE.md mandate). A missing file, a
missing block, an unknown override key, or a malformed YAML → all defaults (the
read NEVER raises; a hostile/broken user YAML must not break a scan).

Config surface:

  * ``top_n``                 headline cap (1..25); the Top-N selection draws at
                              most this many ELIGIBLE findings (no padding).
  * ``epss_enabled``          opt-in EPSS network egress; default OFF → EPSS
                              unavailable → neutral multiplier 1.0 (D-18-02).
  * ``epss_timeout_seconds``  wall-clock cap on the opt-in EPSS network GET.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

# Documented synthesis defaults. config overrides layer on top at call time.
_DEFAULT_TOP_N: int = 10
_DEFAULT_EPSS_ENABLED: bool = False
_DEFAULT_EPSS_TIMEOUT_SECONDS: int = 15


class SynthesisConfig(BaseModel):
    """Resolved synthesis config (defaults + per-repo override layered).

    Frozen + ``extra='forbid'``: an unexpected key in the user's ``synthesis:``
    block is dropped before construction (see :func:`read_synthesis_config`), so
    the model only ever sees the known surface; the frozen flag makes the resolved
    config immutable for the scan.

    ``epss_enabled`` defaults OFF: the EPSS network reader is NEVER imported on the
    default path (T-18-05). ``top_n`` is bounded ``[1, 25]`` so a hostile config
    cannot demand an unbounded headline.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    top_n: int = Field(default=_DEFAULT_TOP_N, ge=1, le=25)
    epss_enabled: bool = Field(default=_DEFAULT_EPSS_ENABLED)
    epss_timeout_seconds: int = Field(default=_DEFAULT_EPSS_TIMEOUT_SECONDS, ge=1)


# The known override keys — anything else in the user's block is ignored (so an
# unrelated future key cannot trip extra='forbid' and break the scan).
_KNOWN_KEYS: frozenset[str] = frozenset(SynthesisConfig.model_fields)


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``synthesis`` block.

    Read at CALL time via ``ruamel.yaml.YAML(typ='safe')`` (T-18-04). Returns an
    empty dict when the file is absent / unreadable / has no ``synthesis`` block,
    so the documented defaults stand. NEVER raises (a poisoned or malformed user
    YAML must not break a scan).
    """
    override_file = repo_path / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        block = doc.get("synthesis") or {}
        return block if isinstance(block, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def read_synthesis_config(repo_path: Path | str | None) -> SynthesisConfig:
    """Read the repo's ``synthesis`` config, layering it over the defaults.

    Args:
        repo_path: the target repository root. Its ``.repo-audit.yaml`` is
            read at call time; absent file / block → all documented defaults
            (``top_n=10``, ``epss_enabled=False``). ``None`` → defaults.

    Returns:
        A frozen :class:`SynthesisConfig`. Never raises: a missing file, a missing
        block, an unknown override key, or a malformed YAML all degrade to the
        documented defaults.
    """
    if repo_path is None:
        return SynthesisConfig()
    override = _load_repo_override(Path(repo_path))
    # Only pass through known keys; drop unrecognized ones so a future/unrelated
    # key in the user's block cannot trip extra='forbid'.
    kwargs = {k: v for k, v in override.items() if k in _KNOWN_KEYS and v is not None}
    try:
        return SynthesisConfig(**kwargs)
    except Exception:  # noqa: BLE001 — a bad value type never breaks a scan
        return SynthesisConfig()


__all__ = ["SynthesisConfig", "read_synthesis_config"]
