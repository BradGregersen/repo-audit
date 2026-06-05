"""BYO opt-in config block + attestation gate (D-06-06 / SCH-08 / T-06-10).

A scoped, typed loader for the ``byo_tools`` block of ``.repo-audit.yaml``
ONLY — this is deliberately NOT a general config system (there is no
centralized loader in Phase 6; collectors still read config ad-hoc). The block
declares per-tool opt-in entries for arbitrary SARIF/JSON-emitting commercial
tools:

    byo_tools:
      acme-scanner:
        enabled: true                 # default false
        use_rights_attestation: true  # default false — MUST be true to run
        credential_env: ACME_TOKEN    # env-var NAME holding the token (never the token)
        sarif_output: .acme/out.sarif # path the tool writes its SARIF to
        default_dimension: security
        severity_map: {error: critical}

Security posture
----------------
- **Attestation gate (D-06-06 / T-06-08):** :attr:`ByoToolConfig.should_run` is
  True ONLY when ``enabled`` AND ``use_rights_attestation`` are BOTH True.
  Default construction (no attestation) => never runs.
- **SCH-08 / T-06-09:** there is NO field that stores a secret VALUE.
  ``credential_env`` is an env-var NAME. ``extra='forbid'`` rejects a stray
  ``token`` / ``credential`` / ``secret`` key in the YAML at validation time.
- **T-06-10:** the YAML is loaded with ruamel ``YAML(typ='safe')`` — refuses
  ``!!python/object`` / ``!!python/name`` constructors, mirroring the
  TypeScript adapter's safe-loader posture (T-03-01).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

from repo_audit.schema.enums import Dimension


class ByoToolConfig(BaseModel):
    """A single BYO opt-in tool entry from ``.repo-audit.yaml``.

    ``extra='forbid'`` (SCH-08 lineage) means a stray ``token`` / ``credential``
    / ``secret`` key — or any typo — raises ``ValidationError`` before the object
    exists. Secrets are referenced by env-var NAME (``credential_env``), never
    stored here.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    enabled: bool = False  # DEFAULT OFF
    use_rights_attestation: bool = False  # DEFAULT OFF — must be True to run
    credential_env: str | None = None  # env-var NAME only (SCH-08: never the token)
    sarif_output: str = Field(..., min_length=1)  # path the tool writes its SARIF to
    default_dimension: Dimension  # validated against the 7-value Literal
    severity_map: dict[str, str] = Field(default_factory=dict)
    # Phase-16 (BYO-02): hard wall-clock bound for the live commercial-tool
    # invocation at the run_byo_tool seam. Additive — Phase-6 pre-written-SARIF
    # callers (no produce-argv) never reach the invocation and so never use it.
    timeout_seconds: int = 600

    @property
    def should_run(self) -> bool:
        """The attestation gate (D-06-06).

        A BYO tool runs ONLY when it is explicitly enabled AND the user has
        attested they hold the rights to use it. Either flag absent/false => the
        tool never runs (default-OFF, license-clean standard build, CRIT-7).
        """
        return self.enabled and self.use_rights_attestation


def _safe_yaml() -> YAML:
    """ruamel YAML in safe mode (T-06-10 / T-03-01).

    Factored into its own callable so the safe-mode posture is greppable for the
    source-string test ``test_yaml_loaded_in_safe_mode``.
    """
    return YAML(typ="safe")


def load_byo_config(yaml_path: str | Path) -> dict[str, ByoToolConfig]:
    """Load the ``byo_tools`` block of ``.repo-audit.yaml``.

    Args:
        yaml_path: path to a ``.repo-audit.yaml`` file.

    Returns:
        ``{tool_name: ByoToolConfig}``. A missing file or a missing/empty
        ``byo_tools`` block yields ``{}`` (graceful — a repo without BYO config
        must not crash the scan).

    Raises:
        pydantic ``ValidationError``: if a ``byo_tools`` entry is malformed
            (unknown key incl. a stray secret key, wrong type, invalid
            dimension). This is fail-loud: a mis-declared opt-in tool — or a
            secret smuggled into config — must not be silently dropped.
    """
    path = Path(yaml_path)
    if not path.is_file():
        return {}

    yaml = _safe_yaml()
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh)

    if not isinstance(data, dict):
        return {}

    byo_block = data.get("byo_tools")
    if not isinstance(byo_block, dict):
        return {}

    tools: dict[str, ByoToolConfig] = {}
    for tool_name, entry in byo_block.items():
        fields: dict[str, Any] = dict(entry) if isinstance(entry, dict) else {}
        # The mapping key is the canonical tool name; inject it so the body need
        # not repeat it (and so a body `name` mismatch can't shadow the key).
        fields["name"] = str(tool_name)
        tools[str(tool_name)] = ByoToolConfig.model_validate(fields)

    return tools


__all__ = ["ByoToolConfig", "load_byo_config"]
