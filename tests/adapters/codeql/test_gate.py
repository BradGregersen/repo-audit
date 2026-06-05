"""CodeQL default-OFF gate contract (DSAST-01, Plan 16-04).

Pins the load-bearing default-OFF posture:
  * default construction (no enable / no attestation / no ground) -> should_run False;
  * should_run is True ONLY when enabled AND use_rights_attestation AND a
    use_rights ground is set (D-16-08 — BOTH the ground and the attestation);
  * a stray secret-value key (token/secret) in the codeql: block -> ValidationError
    (extra='forbid' inherited from ByoToolConfig);
  * credential_env stores an env-var NAME only — no field stores a secret value.
"""
from __future__ import annotations

import pytest

from repo_audit.adapters.codeql.config import CodeQlConfig


def _base_kwargs(**overrides):
    kw = dict(
        name="codeql",
        sarif_output="codeql.sarif",
        default_dimension="security",
    )
    kw.update(overrides)
    return kw


def test_default_off():
    """Default construction never runs (license-clean standard build)."""
    cfg = CodeQlConfig(**_base_kwargs())
    assert cfg.should_run is False


def test_attestation_alone_does_not_run():
    """enabled + attestation WITHOUT a ground still does NOT run (D-16-08)."""
    cfg = CodeQlConfig(
        **_base_kwargs(enabled=True, use_rights_attestation=True)
    )
    assert cfg.use_rights is None
    assert cfg.should_run is False


def test_ground_alone_does_not_run():
    """A ground WITHOUT the attestation flag still does NOT run (D-16-08)."""
    cfg = CodeQlConfig(
        **_base_kwargs(enabled=True, use_rights="personal-own-code")
    )
    assert cfg.should_run is False


def test_all_three_required_runs():
    """enabled AND attestation AND a ground -> should_run True."""
    cfg = CodeQlConfig(
        **_base_kwargs(
            enabled=True,
            use_rights_attestation=True,
            use_rights="ghas",
        )
    )
    assert cfg.should_run is True


@pytest.mark.parametrize("ground", ["oss", "ghas", "personal-own-code"])
def test_valid_grounds(ground):
    cfg = CodeQlConfig(
        **_base_kwargs(
            enabled=True, use_rights_attestation=True, use_rights=ground
        )
    )
    assert cfg.should_run is True


def test_invalid_ground_rejected():
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        CodeQlConfig(**_base_kwargs(use_rights="commercial-someone-elses-code"))


def test_stray_secret_key_rejected():
    """extra='forbid' (inherited) rejects a smuggled token/secret key."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        CodeQlConfig(
            **_base_kwargs(
                enabled=True,
                use_rights_attestation=True,
                use_rights="ghas",
                token="oops",  # type: ignore[call-arg]
            )
        )


def test_credential_env_is_name_only():
    """credential_env stores an env-var NAME, never a secret VALUE."""
    cfg = CodeQlConfig(**_base_kwargs(credential_env="GHAS_TOKEN"))
    assert cfg.credential_env == "GHAS_TOKEN"
    # No secret-value field exists on the model.
    fields = set(CodeQlConfig.model_fields)
    assert "token" not in fields
    assert "secret" not in fields
    assert "api_key" not in fields


def test_timeout_long_cap_default():
    cfg = CodeQlConfig(**_base_kwargs())
    assert cfg.timeout_seconds == 1800
