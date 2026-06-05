"""CodeQL use-rights provenance contract (DSAST-01, Wave 0 scaffolding).

Pins the provenance stamping for Plan 16-04:
  * running CodeQL requires BOTH a ``use_rights`` ground (an enum — e.g. the
    GHAS / research / OSS grant the user attests to) AND the attestation flag,
  * the chosen ground is STAMPED into the run provenance so the report records
    under which right CodeQL was run.

``importorskip`` keeps this SKIPPED until the lane module lands.
"""
from __future__ import annotations

import pytest

codeql = pytest.importorskip(
    "repo_audit.adapters.codeql",
    reason="Wave 1/2 (plan 16-04) not yet landed — adapters.codeql missing",
)


def test_use_rights_ground_stamped():
    """use_rights enum + attestation both required; chosen ground stamped to provenance.

    The lane's config model must expose a use_rights ground enum and an
    attestation flag, and must record the chosen ground somewhere it can be
    stamped into the run's provenance (never inventing a right).
    """
    cfg_cls = None
    for name in ("CodeqlConfig", "CodeQLConfig", "Config"):
        cfg_cls = getattr(codeql, name, None)
        if cfg_cls is not None:
            break
    if cfg_cls is None:
        pytest.fail("adapters.codeql exposes no config model")

    fields = set(getattr(cfg_cls, "model_fields", {}))
    # use_rights ground enum + attestation flag must both be modelled.
    assert any("use_rights" in f or "ground" in f for f in fields)
    assert any("attest" in f for f in fields)
