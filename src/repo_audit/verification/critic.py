"""The bounded adversarial critic — a SECOND, isolated ClaudeSDKClient (VER-03).

This module is the critic counterpart to ``agent/session.py`` + ``agent/tools.py``
+ ``agent/options.py``, cloned and narrowed for adversarial review:

  * ``submit_verdict`` — the LLM → Python boundary tool (clone of ``emit_report``).
    The handler runs the deterministic ``_citation_is_valid`` over a "refuted"
    verdict's citation; an uncited/invalid refutation is DISCARDED (logged, NO
    repair retry, zero rung effect — D-17-15). The LLM is advisory; Python is
    authoritative.
  * ``get_repo_excerpt`` — a READ-ONLY evidence getter so the critic can verify
    its own citation against real source before submitting (RESEARCH Open Q3).
    It reads a bounded line range and can never write.
  * ``_citation_is_valid`` — the load-bearing control (Pitfall 4). Deterministic
    Python that resolves ``file_line`` / ``lockfile`` / ``policy`` against the
    real repo and ``sibling_ref`` against the current finding set. Never raises:
    any I/O error → ``False``.
  * ``build_critic_options`` — a read-only ``ClaudeAgentOptions`` (V4 / Pitfall 2):
    ``tools=[]`` AND ``allowed_tools`` whitelists ONLY the two ``mcp__critic__*``
    tools, with the ``_FORBIDDEN_BUILTINS`` leak assertion copied from
    ``options.py`` L197-200. The critic can NEVER gain Write/Bash/Edit.

The critic NEVER promotes a rung itself: it emits ``Verdict`` objects only; the
Plan 17-03 stage applies them (and the downgrade-only post-pass is the backstop
against an upgrade attempt).
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from claude_agent_sdk import create_sdk_mcp_server, tool
from pydantic import BaseModel, ConfigDict

from repo_audit.agent.constants import get_threshold
from repo_audit.verification.record import (
    Citation,
    RefutationAngle,
    RefutationRecord,
    build_finding_ref,
)

if TYPE_CHECKING:
    from claude_agent_sdk import ClaudeAgentOptions
    from claude_agent_sdk.types import McpServerConfig

    from repo_audit.schema.finding import Finding


# --- Verdict (the critic's emitted result; the stage consumes it) -----------


class Verdict(BaseModel):
    """The critic's verdict for ONE reviewed finding.

    ``finding_ref`` keys back to the reviewed finding (build_finding_ref).
    ``refutation`` is the surviving RefutationRecord ONLY when the verdict is
    "refuted" with a VALID citation; on "survived" or a discarded refutation it
    is None. The critic emits this — it does NOT touch the finding's rung. The
    Plan 17-03 stage applies refuted verdicts (downgrade-only).
    """

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    outcome: Literal["refuted", "survived"]
    refutation: RefutationRecord | None = None


# --- VerdictPayload (the LLM-supplied submit_verdict argument shape) ---------


class VerdictPayload(BaseModel):
    """The argument shape the critic LLM passes to ``submit_verdict``.

    ``extra='forbid'`` so a hallucinated field is rejected at the boundary
    (defense-in-depth, mirroring ``emit_report``). The LLM is advisory: the
    handler re-validates the citation deterministically before any effect.
    """

    model_config = ConfigDict(extra="forbid")

    outcome: Literal["refuted", "survived"]
    angle: RefutationAngle | None = None
    citation: Citation | None = None
    reason: str = ""


# --- Per-candidate critic state ---------------------------------------------
#
# The @tool handlers cannot accept the repo path / finding set as parameters
# (the SDK passes ``args: dict`` only), so the loop stashes per-candidate
# context in module-level state — the same pattern ``agent/tools.py`` uses for
# ``_RESULTS``. ``reset_critic_state`` is called BEFORE each candidate's session
# so a prior candidate's verdict can never bleed into the next.

_REPO_PATH: Path | None = None
_FINDING_SET: list = []
_CANDIDATE_REF: str = ""
_SUBMITTED_VERDICT: Verdict | None = None
_DISCARDED: list[RefutationRecord] = []


def reset_critic_state(
    *,
    repo_path: "Path | str | None",
    finding_set: "list[Finding]",
    candidate_ref: str = "",
) -> None:
    """Reset per-candidate critic state before a submit_verdict turn.

    ``repo_path`` resolves ``file_line`` citations + ``get_repo_excerpt`` reads.
    ``finding_set`` resolves ``sibling_ref`` citations (the duplicate angle).
    ``candidate_ref`` is the reviewed finding's fingerprint (for the Verdict).
    """
    global _REPO_PATH, _FINDING_SET, _CANDIDATE_REF, _SUBMITTED_VERDICT, _DISCARDED
    _REPO_PATH = Path(repo_path) if repo_path is not None else None
    _FINDING_SET = list(finding_set)
    _CANDIDATE_REF = candidate_ref
    _SUBMITTED_VERDICT = None
    _DISCARDED = []


def get_submitted_verdict() -> Verdict | None:
    """Return the Verdict stored by the most recent submit_verdict call (if any)."""
    return _SUBMITTED_VERDICT


def get_discarded() -> list[RefutationRecord]:
    """Return the discarded (invalid-citation) refutations for the current candidate."""
    return list(_DISCARDED)


# --- _citation_is_valid — the load-bearing deterministic control (Pitfall 4) -


def _citation_is_valid(
    citation: "Citation | None",
    repo_path: "Path | str | None",
    finding_set: "list[Finding]",
) -> bool:
    """Resolve a refutation citation against the real repo / finding set.

    THE control: the LLM's "refuted" verdict has NO effect unless its citation
    resolves here in deterministic Python (D-17-15 / Pitfall 4). Never raises —
    any I/O / parse error folds to ``False`` (an unresolvable citation is treated
    as uncited and discarded).

      * ``file_line``  → ``file`` exists under ``repo_path`` AND ``1 <= line``
                         is within the file's line count.
      * ``lockfile``   → ``lockfile_entry`` is a non-empty token found in a
                         lockfile under ``repo_path``.
      * ``policy``     → ``policy_ref`` is a recognized policy statement.
      * ``sibling_ref``→ ``sibling_finding_ref`` matches a ``build_finding_ref``
                         of a finding in ``finding_set``.
    """
    if citation is None:
        return False
    try:
        kind = citation.kind
        if kind == "file_line":
            if repo_path is None or not citation.file or citation.line is None:
                return False
            target = Path(repo_path) / citation.file
            if not target.is_file():
                return False
            line = citation.line
            if line < 1:
                return False
            # Bounded line-count read; any decode error → False.
            with target.open("r", encoding="utf-8", errors="replace") as fh:
                n_lines = sum(1 for _ in fh)
            return 1 <= line <= n_lines

        if kind == "lockfile":
            entry = (citation.lockfile_entry or "").strip()
            if not entry or repo_path is None:
                return False
            return _lockfile_entry_present(Path(repo_path), entry)

        if kind == "policy":
            ref = (citation.policy_ref or "").strip()
            return _is_recognized_policy(ref)

        if kind == "sibling_ref":
            ref = (citation.sibling_finding_ref or "").strip()
            if not ref:
                return False
            known = {build_finding_ref(f) for f in finding_set}
            return ref in known
    except Exception:
        return False
    return False


# Lockfiles the critic may cite an entry against (read-only existence/grep).
_LOCKFILE_NAMES: tuple[str, ...] = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "go.sum",
    "requirements.txt",
)

# Recognized policy statement prefixes (a real policy ref names one of these).
_RECOGNIZED_POLICY_PREFIXES: tuple[str, ...] = (
    "SECURITY.md",
    "CODEOWNERS",
    ".repo-audit.yaml",
    "policy:",
)


def _lockfile_entry_present(repo_path: Path, entry: str) -> bool:
    """True if ``entry`` appears verbatim in a recognized lockfile (never raises)."""
    for name in _LOCKFILE_NAMES:
        lock = repo_path / name
        if not lock.is_file():
            continue
        try:
            text = lock.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if entry in text:
            return True
    return False


def _is_recognized_policy(ref: str) -> bool:
    """True if ``ref`` names a recognized policy statement (deterministic table)."""
    if not ref:
        return False
    return any(ref.startswith(prefix) for prefix in _RECOGNIZED_POLICY_PREFIXES)


# --- submit_verdict — the LLM → Python boundary (clone of emit_report) -------


def _wrap(payload: object) -> dict[str, Any]:
    """Wrap a serializable payload as the SDK tool-result envelope."""
    import json

    return {"content": [{"type": "text", "text": json.dumps(payload, default=str)}]}


@tool(
    "submit_verdict",
    (
        "Submit your verdict for the candidate finding EXACTLY ONCE. outcome is "
        "'refuted' (you killed it) or 'survived' (it stands). A 'refuted' verdict "
        "MUST carry a citation that resolves against the real repository — a real "
        "file:line, a lockfile entry, a recognized policy statement, or (for the "
        "'duplicate' angle) a sibling_ref whose sibling_finding_ref EXACTLY "
        "matches a queued sibling fingerprint. An uncited or unresolvable "
        "refutation is DISCARDED: logged, no retry, zero effect on the finding. "
        "When you cannot back a refutation with real evidence, submit 'survived'."
    ),
    VerdictPayload.model_json_schema(),
)
async def submit_verdict(args: dict[str, Any]) -> dict[str, Any]:
    """D-17-15 boundary: validate the payload, then deterministically re-check
    the citation before the refutation has ANY effect.

    Unlike ``emit_report``, an invalid citation does NOT trigger an is_error
    repair retry — the refutation is simply DISCARDED (recorded with
    citation_valid=False) and the turn accepted inert. The finding stays at its
    deterministic rung.
    """
    global _SUBMITTED_VERDICT
    try:
        payload = VerdictPayload.model_validate(args)
    except Exception as exc:  # pydantic.ValidationError — malformed payload
        # A malformed payload is treated as "no usable verdict": inert, no retry.
        return _wrap({"status": "rejected", "message": f"invalid payload: {exc}"})

    if payload.outcome == "survived":
        _SUBMITTED_VERDICT = Verdict(
            finding_ref=_CANDIDATE_REF, outcome="survived", refutation=None
        )
        return _wrap({"status": "ok", "message": "Verdict recorded: survived."})

    # outcome == "refuted": the citation is the load-bearing gate.
    valid = _citation_is_valid(payload.citation, _REPO_PATH, _FINDING_SET)
    # A refuted verdict with no angle/citation cannot be valid.
    angle = payload.angle or "static_read_as_runtime"
    citation = payload.citation or Citation(kind="file_line")
    record = RefutationRecord(
        angle=angle,
        citation=citation,
        reason=payload.reason,
        citation_valid=valid,
    )
    if not valid:
        # D-17-15: DISCARD — log it, no retry, zero rung effect. The finding
        # survives by default (no surviving verdict stored).
        _DISCARDED.append(record)
        return _wrap(
            {
                "status": "discarded",
                "message": (
                    "Refutation DISCARDED — citation did not resolve against the "
                    "real repository. The finding stands. No retry."
                ),
            }
        )

    _SUBMITTED_VERDICT = Verdict(
        finding_ref=_CANDIDATE_REF, outcome="refuted", refutation=record
    )
    return _wrap({"status": "ok", "message": "Verdict recorded: refuted (citation valid)."})


# --- get_repo_excerpt — read-only evidence getter (never writes/raises) ------


@tool(
    "get_repo_excerpt",
    (
        "READ-ONLY: return a bounded slice of a file's source text so you can "
        "verify your intended citation against real source before submitting. "
        "Args: file (repo-relative path), line_range ([start, end], 1-based "
        "inclusive). Returns the text of those lines. On a missing file or "
        "out-of-range request it returns a 'not found' payload — it never "
        "modifies the repository."
    ),
    {
        "type": "object",
        "properties": {
            "file": {"type": "string"},
            "line_range": {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 2,
            },
        },
        "required": ["file", "line_range"],
    },
)
async def get_repo_excerpt(args: dict[str, Any]) -> dict[str, Any]:
    """Read-only bounded excerpt. Never writes; never raises (folds to inert)."""
    try:
        rel = str(args.get("file", "") or "")
        line_range = args.get("line_range") or [1, 1]
        start = int(line_range[0])
        end = int(line_range[1])
        if _REPO_PATH is None or not rel:
            return _wrap({"status": "not_found", "text": ""})
        target = _REPO_PATH / rel
        if not target.is_file():
            return _wrap({"status": "not_found", "text": ""})
        if start < 1:
            start = 1
        # Cap the window so a hostile request cannot ask for an unbounded read.
        end = min(end, start + 199)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        excerpt = "\n".join(lines[start - 1 : end])
        return _wrap({"status": "ok", "file": rel, "text": excerpt})
    except Exception:
        # Read-only + never-raise: fold every error to an inert not_found.
        return _wrap({"status": "not_found", "text": ""})


# --- read-only options builder (clone of options.build_options) -------------

# The critic's allow-list — EXACTLY the two read-only MCP tools. Order is fixed
# so the read-only assertion test can pin it.
_CRITIC_ALLOWED_TOOLS: list[str] = [
    "mcp__critic__submit_verdict",
    "mcp__critic__get_repo_excerpt",
]

# Built-in tool names that must NEVER appear in allowed_tools (copied from
# options.py L87-96). ``tools=[]`` strips them structurally; this powers the
# defense-in-depth leak assertion.
_FORBIDDEN_BUILTINS: tuple[str, ...] = (
    "Write",
    "Bash",
    "Read",
    "Edit",
    "WebSearch",
    "WebFetch",
    "NotebookEdit",
    "TodoWrite",
)


def build_critic_mcp_server() -> "McpServerConfig":
    """Register the critic's two read-only tools as an in-process MCP server."""
    return create_sdk_mcp_server(
        name="critic", version="1", tools=[submit_verdict, get_repo_excerpt]
    )


def build_critic_options(
    *,
    mcp_server: "McpServerConfig",
    system_prompt: str,
) -> "ClaudeAgentOptions":
    """Build the read-only critic ClaudeAgentOptions (V4 / Pitfall 2).

    ``tools=[]`` strips ALL built-ins; ``allowed_tools`` whitelists ONLY the two
    read-only ``mcp__critic__*`` tools. Budgets read the separate ``critic.*``
    knobs. The ``_FORBIDDEN_BUILTINS`` leak assertion (copied from options.py
    L197-200) fails the build if a Write/Bash/Edit name ever slips in.
    """
    from claude_agent_sdk import ClaudeAgentOptions

    allowed = list(_CRITIC_ALLOWED_TOOLS)
    # Defense-in-depth: assert no built-in tool name leaked into allowed_tools.
    for forbidden in _FORBIDDEN_BUILTINS:
        assert forbidden not in allowed, (
            f"AGENT-03 violation: {forbidden!r} appeared in critic allowed_tools"
        )

    return ClaudeAgentOptions(
        tools=[],  # strip ALL built-ins (Pitfall 2)
        allowed_tools=allowed,
        mcp_servers={"critic": mcp_server},
        max_turns=get_threshold("critic.max_turns"),
        max_budget_usd=get_threshold("critic.max_budget_usd"),
        system_prompt=system_prompt,
        permission_mode="bypassPermissions",
    )


__all__ = [
    "Verdict",
    "VerdictPayload",
    "submit_verdict",
    "get_repo_excerpt",
    "build_critic_mcp_server",
    "build_critic_options",
    "_citation_is_valid",
    "reset_critic_state",
    "get_submitted_verdict",
    "get_discarded",
]
