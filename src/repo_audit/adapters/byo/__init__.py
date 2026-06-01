"""Generic bring-your-own (BYO) commercial-tool opt-in adapter (BYO-01 / SC-6).

The PATTERN — not any specific commercial tool — lands in Phase 6 (D-06-08).
A tool that emits SARIF/JSON is registered + enabled per-tool via
``.repo-audit.yaml`` carrying a **use-rights attestation flag (default
OFF)** plus a **credential ENV-VAR NAME** (never a raw token, SCH-08). A tool
with no attestation NEVER runs (D-06-06). When enabled+attested, its SARIF
flows through the SAME ``sarif_to_findings`` pipeline every OSS tool uses,
tagging ``source_tool`` (BYO-01 traceability).

The six pre-named commercial tools (Semgrep Pro, Socket.dev, GitGuardian,
Snyk, SonarCloud, GHAS-CodeQL) are deferred to Phase 16 — only the pattern +
one synthetic proof-fixture land here (D-06-14).

``run_byo_tool`` (the generic adapter) is exported lazily via
:func:`__getattr__` so importing the lighter ``config`` module does not pull in
the adapter/SARIF parse path until it is actually used.
"""
from typing import Any

from repo_audit.adapters.byo.config import ByoToolConfig, load_byo_config

__all__ = ["ByoToolConfig", "load_byo_config", "run_byo_tool"]


def __getattr__(name: str) -> Any:
    if name == "run_byo_tool":
        from repo_audit.adapters.byo.adapter import run_byo_tool

        return run_byo_tool
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
