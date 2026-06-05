"""CodeQL opt-in config + typed use-rights ground gate (DSAST-01, Plan 16-04).

``CodeQlConfig`` is a thin SUBCLASS of :class:`ByoToolConfig` — it inherits the
default-OFF attestation posture, ``extra='forbid'`` (rejects a smuggled
``token`` / ``secret`` key), ``credential_env`` (env-var NAME, never a value),
and the shared ``sarif_output`` / ``default_dimension`` / ``severity_map`` BYO
fields. It EXTENDS the gate with a typed *use-rights ground*:

    codeql:
      enabled: true                 # default false
      use_rights_attestation: true  # default false
      use_rights: personal-own-code # oss | ghas | personal-own-code (REQUIRED to run)
      credential_env: GHAS_TOKEN    # env-var NAME holding a GHAS token (never the token)
      default_dimension: security
      timeout_seconds: 1800         # long cap for DB-create + analyze (D-16-09)

Why a typed ground (D-16-08)
----------------------------
Default-OFF keeps the *standard* build license-clean (CodeQL's licence is
restrictive). The typed ground makes the licence posture AUDITABLE — not merely
gated: the report can answer "under which right was CodeQL run?". So
``should_run`` requires ALL THREE — ``enabled`` AND ``use_rights_attestation``
AND a ``use_rights`` ground — and the chosen ground is stamped into provenance
on a successful run (see ``sast/provenance.build_codeql_provenance``).

The block is loaded with the SAME safe-mode ruamel loader the BYO config uses
(``_safe_yaml`` — never PyYAML, CLAUDE.md mandate); a missing ``codeql:`` block
yields ``None`` (the lane stays absent — default OFF).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from repo_audit.adapters.byo.config import ByoToolConfig, _safe_yaml

# The three use-rights grounds a user may attest to (D-16-08). Each names a
# concrete grant under which the user holds the right to run CodeQL:
#   * oss               — CodeQL's free grant for analysing OSS code;
#   * ghas              — a GitHub Advanced Security entitlement;
#   * personal-own-code — the personal/research grant over the user's own code.
UseRightsGround = Literal["oss", "ghas", "personal-own-code"]

# Long wall-clock cap for DB-create + analyze (D-16-09). CodeQL builds a database
# then runs a query suite — far slower than a lint pass — so the default is
# generous and config-overridable (A8). run_tool's SIGTERM->5s->SIGKILL
# escalation backs the no-hang guarantee even at this cap.
_DEFAULT_TIMEOUT_SECONDS = 1800


class CodeQlConfig(ByoToolConfig):
    """The ``codeql:`` opt-in entry — ByoToolConfig + a typed use-rights ground.

    Inherits ``extra='forbid'`` (a stray ``token``/``secret`` key raises
    ``ValidationError`` before the object exists), ``credential_env`` (env-var
    NAME only — SCH-08), and the BYO attestation fields. Adds:

      * ``use_rights`` — the typed ground enum (REQUIRED, with the attestation,
        to run — D-16-08); ``None`` by default so default construction never runs;
      * ``timeout_seconds`` — the long DB-create+analyze cap (D-16-09).
    """

    use_rights: UseRightsGround | None = None
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS

    @property
    def should_run(self) -> bool:
        """The use-rights gate (D-16-08): enabled AND attested AND a ground.

        BOTH the attestation flag AND a concrete ``use_rights`` ground are
        required — an attestation with no named ground does NOT run, and a named
        ground with no attestation does NOT run. Default construction (no
        enable, no attestation, no ground) => never runs (license-clean standard
        build).
        """
        return (
            self.enabled
            and self.use_rights_attestation
            and self.use_rights is not None
        )


def load_codeql_config(yaml_path: str | Path) -> CodeQlConfig | None:
    """Load the ``codeql:`` block of ``.repo-audit.yaml``.

    Args:
        yaml_path: path to a ``.repo-audit.yaml`` file.

    Returns:
        A validated :class:`CodeQlConfig`, or ``None`` when the file or the
        ``codeql:`` block is missing/empty (the lane stays absent — default
        OFF). A missing ``name`` in the block defaults to ``"codeql"``.

    Raises:
        pydantic ``ValidationError``: if the ``codeql:`` block is present but
            malformed (unknown key incl. a stray secret key, invalid ground,
            wrong type). Fail-loud: a mis-declared opt-in tool — or a secret
            smuggled into config — must not be silently dropped.
    """
    path = Path(yaml_path)
    if not path.is_file():
        return None

    yaml = _safe_yaml()
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh)

    if not isinstance(data, dict):
        return None

    block = data.get("codeql")
    if not isinstance(block, dict):
        return None

    fields: dict[str, Any] = dict(block)
    fields.setdefault("name", "codeql")
    return CodeQlConfig.model_validate(fields)


__all__ = ["CodeQlConfig", "UseRightsGround", "load_codeql_config"]
