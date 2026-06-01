"""Attestation-gate + config-loader contract for the BYO opt-in pattern (D-06-06).

These pin the load-bearing default-OFF posture:
- ``ByoToolConfig`` defaults: enabled=False, use_rights_attestation=False, should_run False.
- The D-06-06 assertion: enabled but NOT attested => should_run False (never runs).
- Both flags True => should_run True.
- ``load_byo_config`` reads the ``byo_tools`` block via ruamel YAML(typ='safe').
- Missing file / missing block => empty dict (graceful, no crash).
- Source-string assert that the loader uses YAML(typ='safe') (T-06-10 / Phase 3 discipline).
- SCH-08 lineage: extra='forbid' rejects a stray token/credential/secret key (T-06-09).
- An invalid default_dimension is rejected loudly.

The module gate (importorskip) keeps these SKIPPED until byo/config.py lands,
then they flip ACTIVE (Phase 3 discipline; not xfail-strict).
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

byo_config = pytest.importorskip("repo_audit.adapters.byo.config")

ByoToolConfig = byo_config.ByoToolConfig
load_byo_config = byo_config.load_byo_config


def _min_cfg(**overrides):
    """Construct a ByoToolConfig with the minimal required fields."""
    base = {
        "name": "acme-scanner",
        "sarif_output": "out.sarif",
        "default_dimension": "security",
    }
    base.update(overrides)
    return ByoToolConfig(**base)


# --- should_run gate (D-06-06) -------------------------------------------


def test_default_is_off():
    """A freshly-constructed BYO tool is OFF: no enable, no attestation, no run."""
    cfg = _min_cfg()
    assert cfg.enabled is False
    assert cfg.use_rights_attestation is False
    assert cfg.should_run is False


def test_enabled_but_no_attestation_never_runs():
    """LOAD-BEARING (D-06-06): enabled without attestation MUST NOT run."""
    cfg = _min_cfg(enabled=True, use_rights_attestation=False)
    assert cfg.should_run is False


def test_attested_but_not_enabled_never_runs():
    """Attestation alone is not enough — the tool must also be explicitly enabled."""
    cfg = _min_cfg(enabled=False, use_rights_attestation=True)
    assert cfg.should_run is False


def test_enabled_plus_attestation_runs():
    """Both flags True => should_run True (the only combination that runs)."""
    cfg = _min_cfg(enabled=True, use_rights_attestation=True)
    assert cfg.should_run is True


# --- loader (ruamel safe-mode) -------------------------------------------


_YAML_ONE_TOOL = """\
byo_tools:
  acme-scanner:
    enabled: true
    use_rights_attestation: true
    credential_env: ACME_TOKEN
    sarif_output: .acme/out.sarif
    default_dimension: security
    severity_map:
      error: critical
"""


def test_loader_reads_byo_block(tmp_path: Path):
    """A tmp .repo-audit.yaml with one byo_tools entry loads cleanly."""
    cfg_path = tmp_path / ".repo-audit.yaml"
    cfg_path.write_text(_YAML_ONE_TOOL, encoding="utf-8")

    tools = load_byo_config(cfg_path)

    assert set(tools) == {"acme-scanner"}
    tool = tools["acme-scanner"]
    assert isinstance(tool, ByoToolConfig)
    assert tool.name == "acme-scanner"
    assert tool.enabled is True
    assert tool.use_rights_attestation is True
    assert tool.credential_env == "ACME_TOKEN"
    assert tool.sarif_output == ".acme/out.sarif"
    assert tool.default_dimension == "security"
    assert tool.severity_map == {"error": "critical"}
    assert tool.should_run is True


def test_loader_injects_name_from_key(tmp_path: Path):
    """The mapping key is the tool name even when not repeated in the body."""
    cfg_path = tmp_path / ".repo-audit.yaml"
    cfg_path.write_text(
        "byo_tools:\n"
        "  widget-pro:\n"
        "    sarif_output: w.sarif\n"
        "    default_dimension: quality\n",
        encoding="utf-8",
    )

    tools = load_byo_config(cfg_path)

    assert tools["widget-pro"].name == "widget-pro"


def test_loader_missing_file_returns_empty(tmp_path: Path):
    """A nonexistent config path yields {} rather than raising."""
    assert load_byo_config(tmp_path / "does-not-exist.yaml") == {}


def test_loader_missing_byo_block_returns_empty(tmp_path: Path):
    """A config file without a byo_tools block yields {} (graceful)."""
    cfg_path = tmp_path / ".repo-audit.yaml"
    cfg_path.write_text("some_other_key: 1\n", encoding="utf-8")

    assert load_byo_config(cfg_path) == {}


def test_yaml_loaded_in_safe_mode():
    """T-06-10: config.py loads YAML with typ='safe' (source-string assert)."""
    source = inspect.getsource(byo_config)
    assert "YAML(typ=\"safe\")" in source or "YAML(typ='safe')" in source


# --- SCH-08 lineage: no secret-value field permitted (T-06-09) ----------


@pytest.mark.parametrize("secret_key", ["token", "credential", "secret"])
def test_token_field_forbidden(tmp_path: Path, secret_key: str):
    """extra='forbid' rejects a literal secret key — secrets live in env, not config."""
    cfg_path = tmp_path / ".repo-audit.yaml"
    cfg_path.write_text(
        "byo_tools:\n"
        "  acme-scanner:\n"
        "    sarif_output: out.sarif\n"
        "    default_dimension: security\n"
        f"    {secret_key}: hunter2\n",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_byo_config(cfg_path)


def test_no_secret_value_field_declared():
    """SCH-08 lineage: no field on ByoToolConfig can carry a raw secret value."""
    forbidden = {"token", "credential", "secret", "value", "raw", "password", "key"}
    assert forbidden.isdisjoint(set(ByoToolConfig.model_fields))


# --- dimension validation -------------------------------------------------


def test_invalid_default_dimension_rejected():
    """default_dimension must be a member of the 7-value Dimension Literal."""
    with pytest.raises(ValidationError):
        _min_cfg(default_dimension="bogus")
