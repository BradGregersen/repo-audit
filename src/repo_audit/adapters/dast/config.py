"""Call-time ``.repo-audit.yaml`` ``dast:`` reader (Phase 16, DAST-01).

``read_dast_config(repo_path)`` loads the per-repo ``dast:`` block at CALL time
(the ``quality_depth/config.py::_load_repo_override`` pattern — the D-15-03 →
D-16-10 precedent where the URL IS the opt-in), layering it over the documented
adapter defaults.

THE LOAD-BEARING SAFETY PROPERTY (SC4 / Pitfall 7): ``target_url`` is the ONLY
field that can carry a host into the DAST lane. There is deliberately NO
alternate target-bearing field (no default, no repo-derived URL, no
CLI-flag-derived field) — a target enters the ZAP ``-t`` argv from EXACTLY ONE
source, the explicit config. A repo that does not configure ``dast.target_url``
cannot be scanned (the lane refuses). This makes the no-inference guarantee a
STRUCTURAL property of the config surface.

Security (T-16-05, mirrors T-15-01 / T-15-02): the file is loaded ONLY via
``ruamel.yaml.YAML(typ='safe')`` — the safe loader refuses ``!!python/object`` /
``!!python/name`` so a poisoned repo YAML cannot execute Python at load. The
unsafe full-YAML loader is NEVER imported (CLAUDE.md mandate). A missing file, a
missing block, or a
malformed YAML → all defaults (the read NEVER raises; a hostile/broken user YAML
must not break a scan).

Config surface:

  * ``target_url``       absent → the lane degrades to ``unavailable`` (providing
                         the URL IS the opt-in, D-16-10). The ONLY target source.
  * ``timeout_seconds``  ZAP baseline wall-clock cap passed to ``run_tool``.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

# Documented adapter defaults. config overrides layer on top at call time.
_DEFAULT_TARGET_URL: str | None = None
_DEFAULT_TIMEOUT_SECONDS: int = 300  # ZAP baseline wall-clock cap


class DastConfig(BaseModel):
    """Resolved DAST config (defaults + per-repo override layered).

    Frozen + ``extra='forbid'``: an unexpected key in the user's ``dast:`` block
    is dropped before construction (see :func:`read_dast_config`), so the model
    only ever sees the known surface; the frozen flag makes the resolved config
    immutable for the scan.

    ``target_url`` is the SINGLE source a host can reach the ZAP ``-t`` argv from
    — there is no second target-bearing field by design (SC4 / Pitfall 7).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_url: str | None = Field(default=_DEFAULT_TARGET_URL)
    timeout_seconds: int = Field(default=_DEFAULT_TIMEOUT_SECONDS)


# The known override keys — anything else in the user's block is ignored (so an
# unrelated future key cannot trip extra='forbid' and break the scan).
_KNOWN_KEYS: frozenset[str] = frozenset(DastConfig.model_fields)


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``dast`` block.

    Read at CALL time (SC4) via ``ruamel.yaml.YAML(typ='safe')`` (T-16-05).
    Returns an empty dict when the file is absent / unreadable / has no ``dast``
    block, so the documented defaults stand. NEVER raises (a poisoned or
    malformed user YAML must not break a scan).
    """
    override_file = repo_path / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        block = doc.get("dast") or {}
        return block if isinstance(block, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def read_dast_config(repo_path: Path) -> DastConfig:
    """Read the repo's ``dast`` config, layering it over the defaults.

    Args:
        repo_path: the target repository root. Its ``.repo-audit.yaml`` is
            read at call time; absent file / block → all documented defaults
            (``target_url=None`` → the lane refuses to scan).

    Returns:
        A frozen :class:`DastConfig`. Never raises: a missing file, a missing
        block, an unknown override key, or a malformed YAML all degrade to the
        documented defaults.
    """
    override = _load_repo_override(Path(repo_path))
    # Only pass through known keys; drop unrecognized ones so a future/unrelated
    # key in the user's block cannot trip extra='forbid'.
    kwargs = {k: v for k, v in override.items() if k in _KNOWN_KEYS and v is not None}
    try:
        return DastConfig(**kwargs)
    except Exception:  # noqa: BLE001 — a bad value type never breaks a scan
        return DastConfig()


__all__ = ["DastConfig", "read_dast_config"]
