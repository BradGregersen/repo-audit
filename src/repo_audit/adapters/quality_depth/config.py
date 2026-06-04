"""Call-time ``.repo-audit.yaml`` ``quality_depth:`` reader (Phase 15).

``read_quality_depth_config(repo_path)`` loads the per-repo ``quality_depth:``
block at CALL time (the ``architecture/duplication.py::_load_repo_override``
pattern), layering it over the documented adapter defaults. This honors SC4
per-repo overrides without touching the shipped ``adapter.yaml`` descriptor.

Security (T-15-01 / T-15-02): the file is loaded ONLY via
``ruamel.yaml.YAML(typ='safe')`` — the safe loader refuses ``!!python/object`` /
``!!python/name`` so a poisoned repo YAML cannot execute Python at load. PyYAML
is NEVER imported (CLAUDE.md mandate). A missing file, a missing block, or a
malformed YAML → all defaults (the read NEVER raises; a hostile/broken user YAML
must not break a scan).

Config surface (RESEARCH §Live-URL Config & Egress Gating):

  * ``live_url``               absent → axe + lighthouse degrade to ``unavailable``
                               (providing the URL IS the opt-in, D-15-03)
  * ``web_budget_bytes``       ~250 KB web transfer-size budget (D-15-05)
  * ``rn_budget_bytes``        ~500 KB RN JS-bundle-size budget (D-15-05)
  * ``regression_pct``         % growth vs prior scan that triggers a regression (D-15-04)
  * ``regression_floor_bytes`` ~10 KB noise floor below which growth never flags (D-15-04)
  * ``rn_entry_file``          ``react-native bundle --entry-file`` override (D-15-02)
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

# Documented adapter defaults (mirror adapter.yaml `budgets`). config overrides
# layer on top of these at call time.
_DEFAULT_LIVE_URL: str | None = None
_DEFAULT_WEB_BUDGET_BYTES: int = 256000      # ~250 KB
_DEFAULT_RN_BUDGET_BYTES: int = 512000       # ~500 KB
_DEFAULT_REGRESSION_PCT: float = 10.0        # % growth trigger
_DEFAULT_REGRESSION_FLOOR_BYTES: int = 10240  # ~10 KB noise floor
_DEFAULT_RN_ENTRY_FILE: str = "index.js"


class QualityDepthConfig(BaseModel):
    """Resolved quality-depth config (defaults + per-repo override layered).

    Frozen + ``extra='forbid'``: an unexpected key in the user's
    ``quality_depth:`` block is dropped before construction (see
    :func:`read_quality_depth_config`), so the model only ever sees the known
    surface; the frozen flag makes the resolved config immutable for the scan.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    live_url: str | None = Field(default=_DEFAULT_LIVE_URL)
    web_budget_bytes: int = Field(default=_DEFAULT_WEB_BUDGET_BYTES)
    rn_budget_bytes: int = Field(default=_DEFAULT_RN_BUDGET_BYTES)
    regression_pct: float = Field(default=_DEFAULT_REGRESSION_PCT)
    regression_floor_bytes: int = Field(default=_DEFAULT_REGRESSION_FLOOR_BYTES)
    rn_entry_file: str = Field(default=_DEFAULT_RN_ENTRY_FILE)


# The known override keys — anything else in the user's block is ignored (so an
# unrelated future key cannot trip extra='forbid' and break the scan).
_KNOWN_KEYS: frozenset[str] = frozenset(QualityDepthConfig.model_fields)


def _load_repo_override(repo_path: Path) -> dict:
    """Load the per-repo ``.repo-audit.yaml`` ``quality_depth`` block.

    Read at CALL time (SC4) via ``ruamel.yaml.YAML(typ='safe')`` (T-15-01).
    Returns an empty dict when the file is absent / unreadable / has no
    ``quality_depth`` block, so the documented defaults stand. NEVER raises (a
    poisoned or malformed user YAML must not break a scan — T-15-02).
    """
    override_file = repo_path / ".repo-audit.yaml"
    if not override_file.is_file():
        return {}
    try:
        yaml = YAML(typ="safe")
        with override_file.open(encoding="utf-8") as fh:
            doc = yaml.load(fh) or {}
        block = doc.get("quality_depth") or {}
        return block if isinstance(block, dict) else {}
    except Exception:  # noqa: BLE001 — a poisoned user YAML never breaks a scan
        return {}


def read_quality_depth_config(repo_path: Path) -> QualityDepthConfig:
    """Read the repo's ``quality_depth`` config, layering it over the defaults.

    Args:
        repo_path: the target repository root. Its ``.repo-audit.yaml`` is
            read at call time; absent file / block → all documented defaults.

    Returns:
        A frozen :class:`QualityDepthConfig`. Never raises: a missing file, a
        missing block, an unknown override key, or a malformed YAML all degrade
        to the documented defaults.
    """
    override = _load_repo_override(Path(repo_path))
    # Only pass through known keys; drop unrecognized ones so a future/unrelated
    # key in the user's block cannot trip extra='forbid'.
    kwargs = {k: v for k, v in override.items() if k in _KNOWN_KEYS and v is not None}
    try:
        return QualityDepthConfig(**kwargs)
    except Exception:  # noqa: BLE001 — a bad value type never breaks a scan
        return QualityDepthConfig()


__all__ = ["QualityDepthConfig", "read_quality_depth_config"]
