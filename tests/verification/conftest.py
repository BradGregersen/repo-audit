"""Shared fixtures for the Phase 17 verification-layer tests.

Three fixtures the per-task verification map (17-VALIDATION.md) and every later
plan's `<verify>` bind to:

  * ``fake_finding``         — a per-family factory producing schema-valid
                               ``Finding`` instances (extra='forbid'); defaults to
                               a candidate finding so the rung-cap validator is
                               satisfied without per-test patching.
  * ``fake_repo_with_source``— a tmp_path dir seeding a Python module that imports
                               a known symbol plus a TS/text file containing a
                               known token, for the reachability + citation-validity
                               tests.
  * ``mock_critic_client``   — a no-op placeholder THIS plan (17-01). Plan 17-02
                               Task 3 fleshes out the canned-verdict injection;
                               the fixture NAME is declared now so later tests bind
                               cleanly.

The existing ``fake_repo`` factory (tests/conftest.py) is reused for git seeding
rather than re-implemented here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_audit.schema.finding import Evidence, Finding


# --- Per-family finding factory ---------------------------------------------

# Family presets — (source_tool, dimension, default rule_id shape). The factory
# builds a schema-valid candidate Finding for the chosen family; any field is
# overridable by keyword.
_FAMILY_PRESETS: dict[str, dict[str, object]] = {
    "sca": {"source_tool": "osv", "dimension": "security", "rule_id": "CVE-2026-0001"},
    "sca_grype": {"source_tool": "grype", "dimension": "security", "rule_id": "CVE-2026-0001"},
    "sast": {"source_tool": "semgrep", "dimension": "security", "rule_id": "owasp.a03.injection"},
    "rls": {"source_tool": "pgrls", "dimension": "correctness", "rule_id": "RLS-OPEN-POLICY"},
    "cicd": {"source_tool": "checkov", "dimension": "process", "rule_id": "CKV-001"},
}


@pytest.fixture
def fake_finding():
    """Factory: build a schema-valid ``Finding`` for a chosen family.

    Usage::

        def test_x(fake_finding):
            f = fake_finding()                          # default sca candidate
            g = fake_finding(family="sast", file="a.ts", line=5)
            h = fake_finding(source_tool="grype")       # any field overridable

    Defaults to a ``candidate`` finding at ``severity='major'`` (the rung-cap
    validator forbids critical/blocker at candidate; major is permitted). Pass
    ``confidence='corroborated'`` + ``severity='critical'`` to build a promoted
    finding, supplying ``confidence_caveat`` if ``evidence_type='static'``.
    """

    def _factory(
        *,
        family: str = "sca",
        dimension: str | None = None,
        severity: str = "major",
        file: str | None = "src/app/auth.py",
        line: int | None = 10,
        evidence_type: str = "static",
        confidence: str = "candidate",
        source_tool: str | None = None,
        rule_id: str | None = None,
        confidence_caveat: str | None = None,
        recommendation: str = "",
        output_snippet: str = "",
        parsed_value: dict | None = None,
    ) -> Finding:
        preset = _FAMILY_PRESETS.get(family, _FAMILY_PRESETS["sca"])
        resolved_tool = source_tool if source_tool is not None else preset["source_tool"]
        resolved_dim = dimension if dimension is not None else preset["dimension"]
        resolved_rule = rule_id if rule_id is not None else preset["rule_id"]
        evidence = Evidence(
            tool=str(resolved_tool) or "unknown",
            output_snippet=output_snippet,
            parsed_value=parsed_value or {},
        )
        return Finding(
            dimension=resolved_dim,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            file=file,
            line=line,
            evidence=evidence,
            evidence_type=evidence_type,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            recommendation=recommendation,
            source_tool=str(resolved_tool),
            source_collector=str(resolved_tool),
            rule_id=str(resolved_rule),
            confidence_caveat=confidence_caveat,
        )

    return _factory


# --- Repo with real source for reachability + citation-validity -------------


@pytest.fixture
def fake_repo_with_source(tmp_path) -> Path:
    """A tmp_path dir with a Python module importing a known symbol + a TS token.

    Layout::

        <repo>/
          src/app/auth.py    -> ``from secrets import token_hex`` (importable symbol)
          src/app/ui.ts      -> contains the token ``dangerouslySetInnerHTML``

    The Python module makes ``check_reachable`` for symbol ``token_hex`` return
    True and for an absent symbol (e.g. ``nonexistent_symbol``) return False. The
    TS file gives the non-Python grep path a known present/absent token to assert.
    """
    repo = tmp_path / "reachability-repo"
    (repo / "src" / "app").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "app" / "auth.py").write_text(
        "from secrets import token_hex\n\n\ndef make_token() -> str:\n"
        "    return token_hex(16)\n",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "ui.ts").write_text(
        "export const Comp = () => "
        "(<div dangerouslySetInnerHTML={{__html: html}} />);\n",
        encoding="utf-8",
    )
    return repo


# --- Critic client stub (fleshed out in Plan 17-02 Task 3) -------------------


@pytest.fixture
def mock_critic_client():
    """Canned-verdict critic-client factory — the ``submit_verdict`` injection seam.

    Replaces the live ``ClaudeSDKClient`` in ``run_critic_session`` so the
    priority-queue + budget + never-raise loop is exercised without the SDK.

    Usage::

        client_factory = mock_critic_client(verdicts=[
            {"outcome": "survived"},                       # candidate 0
            {"outcome": "refuted", "angle": "duplicate",   # candidate 1
             "citation": {...}, "reason": "..."},
            {"raise": True},                               # candidate 2: SDK error
        ])
        verdicts, meta = await run_critic_session(..., client_factory=client_factory)

    Each list entry corresponds to one queued candidate (consumed in order):
      * a dict shaped like a ``submit_verdict`` payload → the mock invokes the
        REAL ``submit_verdict.handler`` (so the citation validator still runs)
        after the loop has called ``reset_critic_state`` for that candidate;
      * ``{"raise": True}`` → the mock client raises inside its session so the
        loop's ``except Exception: continue`` never-raise path is exercised.

    The returned object is a ``client_factory(candidate, repo_path, finding_set,
    candidate_ref)`` callable returning an async-context-manager client whose
    ``run_once()`` applies the canned verdict for that candidate.
    """
    from repo_audit.verification import critic as _critic

    def _make_factory(*, verdicts):
        seq = list(verdicts)
        counter = {"i": 0}

        class _MockClient:
            def __init__(self, candidate_ref: str):
                self._candidate_ref = candidate_ref
                self._spec = seq[counter["i"]] if counter["i"] < len(seq) else {}
                counter["i"] += 1

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def run_once(self):
                """Apply the canned verdict for this candidate (or raise)."""
                if self._spec.get("raise"):
                    raise RuntimeError("simulated SDK failure for this candidate")
                # Invoke the REAL submit_verdict handler so the deterministic
                # citation validator still gates the canned refutation.
                await _critic.submit_verdict.handler(
                    {
                        "outcome": self._spec.get("outcome", "survived"),
                        "angle": self._spec.get("angle"),
                        "citation": self._spec.get("citation"),
                        "reason": self._spec.get("reason", ""),
                    }
                )

        def _factory(*, candidate_ref: str, **_kwargs):
            return _MockClient(candidate_ref)

        return _factory

    return _make_factory
