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

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal

from claude_agent_sdk import create_sdk_mcp_server, tool
from jinja2 import Environment, PackageLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, Field

from repo_audit.agent.constants import get_threshold
from repo_audit.verification.record import (
    Citation,
    RefutationAngle,
    RefutationRecord,
    VerificationRecord,
    build_finding_ref,
)

if TYPE_CHECKING:
    from claude_agent_sdk import ClaudeAgentOptions
    from claude_agent_sdk.types import McpServerConfig

    from repo_audit.schema.finding import Finding


# Severity rank (mirrors agent/tools.py L50-56). Lower = more severe → sorts
# first. Only high-severity (+ corroborated) findings enter the critic queue.
_SEVERITY_RANK: dict[str, int] = {
    "blocker": 0,
    "critical": 1,
    "major": 2,
    "minor": 3,
    "info": 4,
}

# Severities that ALWAYS qualify for review regardless of corroboration (D-17-09).
_HIGH_SEVERITIES: frozenset[str] = frozenset({"blocker", "critical"})

# Corroboration tiers that count as "corroborated" for queue inclusion. ``none``
# is excluded; the five real tiers/signals qualify a lower-severity finding.
_CORROBORATED_TIERS: frozenset[str] = frozenset(
    {"identity", "locus", "coarse", "reachability", "runtime"}
)

# Tier strength for the priority sort (lower = stronger). Mirrors corroborate.py
# _TIER_STRENGTH so the queue's corroboration_strength ordering is consistent.
_TIER_STRENGTH: dict[str, int] = {
    "identity": 0,
    "locus": 1,
    "coarse": 2,
    "reachability": 3,
    "runtime": 4,
    "none": 99,
}


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
    # 17-04: the per-candidate IDENTITY token (the corroboration-stage zero-based
    # input index). ``finding_ref`` is NON-unique (collides for two findings from
    # the same tool at the same locus), so the stage dispatches verdicts by THIS
    # token, not by finding_ref. finding_ref stays the display/audit string.
    candidate_token: int = -1
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
# 17-04: the per-candidate IDENTITY token for the finding currently under review.
# submit_verdict stamps it onto the Verdict so the stage can dispatch by identity
# (not by the non-unique _CANDIDATE_REF fingerprint).
_CANDIDATE_TOKEN: int = -1
_SUBMITTED_VERDICT: Verdict | None = None
_DISCARDED: list[RefutationRecord] = []


def reset_critic_state(
    *,
    repo_path: "Path | str | None",
    finding_set: "list[Finding]",
    candidate_ref: str = "",
    candidate_token: int = -1,
) -> None:
    """Reset per-candidate critic state before a submit_verdict turn.

    ``repo_path`` resolves ``file_line`` citations + ``get_repo_excerpt`` reads.
    ``finding_set`` resolves ``sibling_ref`` citations (the duplicate angle).
    ``candidate_ref`` is the reviewed finding's fingerprint (for the Verdict's
    display/audit field). ``candidate_token`` (17-04) is the reviewed finding's
    per-candidate IDENTITY token — the verdict/tier dispatch key the stage uses
    instead of the non-unique fingerprint.
    """
    global _REPO_PATH, _FINDING_SET, _CANDIDATE_REF, _CANDIDATE_TOKEN
    global _SUBMITTED_VERDICT, _DISCARDED
    _REPO_PATH = Path(repo_path) if repo_path is not None else None
    _FINDING_SET = list(finding_set)
    _CANDIDATE_REF = candidate_ref
    _CANDIDATE_TOKEN = candidate_token
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
            finding_ref=_CANDIDATE_REF,
            candidate_token=_CANDIDATE_TOKEN,
            outcome="survived",
            refutation=None,
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
        finding_ref=_CANDIDATE_REF,
        candidate_token=_CANDIDATE_TOKEN,
        outcome="refuted",
        refutation=record,
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


# --- VerificationMeta — honest-partial N-of-M disclosure (CRIT-5) -----------


class VerificationMeta(BaseModel):
    """Critic-session meta carrying the honest-partial N-of-M disclosure.

    ``critic_reviewed`` (N) < ``critic_total_queue`` (M) means the budget bound
    stopped the queue before every candidate was reviewed; un-reviewed findings
    stay at their deterministic rung (the caller renders "N of M reviewed").
    """

    model_config = ConfigDict(extra="forbid")

    critic_reviewed: int = 0
    critic_total_queue: int = 0
    critic_tokens: int = 0
    discarded_refutations: list[RefutationRecord] = Field(default_factory=list)


# --- build_priority_queue — deterministic high-severity subset (SC-5) -------


def build_priority_queue(
    findings: "list[Finding]",
    records: "list[VerificationRecord]",
) -> "list[Finding]":
    """Return the deterministically-ordered subset of findings to review.

    Inclusion (D-17-09): a finding qualifies if it is high-severity
    (blocker/critical) OR its VerificationRecord corroboration_tier is a real
    tier (identity/locus/coarse/reachability/runtime). Low/info findings that are
    NOT corroborated are dropped.

    Order (SC-5 / Pitfall 5): the stable ``_summarize``-style key
    ``(severity_rank, corroboration_strength, file, line, rule_id)`` so identical
    inputs → identical first-N reviewed set regardless of input ordering. The
    corroboration_strength term sorts a stronger tier ahead of a weaker one at
    equal severity.
    """
    # NOTE (17-04): this tier_by_ref lookup is READ-ONLY for ORDERING/qualification
    # only — it is NOT a dispatch key. Verdict/tier DISPATCH is keyed by the
    # per-candidate identity token (candidate_token) downstream in _apply_verdicts;
    # a fingerprint collision here only affects sort order among equal-keyed
    # findings (already deterministic), never which verdict applies to which finding.
    tier_by_ref: dict[str, str] = {
        r.finding_ref: r.corroboration_tier for r in records
    }

    def _qualifies(f: "Finding") -> bool:
        sev = getattr(f, "severity", "")
        if sev in _HIGH_SEVERITIES:
            return True
        tier = tier_by_ref.get(build_finding_ref(f), "none")
        return tier in _CORROBORATED_TIERS

    candidates = [f for f in findings if _qualifies(f)]

    def _sort_key(f: "Finding"):
        tier = tier_by_ref.get(build_finding_ref(f), "none")
        return (
            _SEVERITY_RANK.get(getattr(f, "severity", ""), len(_SEVERITY_RANK)),
            _TIER_STRENGTH.get(tier, 99),
            getattr(f, "file", None) or "",
            getattr(f, "line", None) if getattr(f, "line", None) is not None else -1,
            getattr(f, "rule_id", "") or "",
        )

    return sorted(candidates, key=_sort_key)


# --- prompt rendering (clone of options._render_system_prompt) --------------


def _render_critic_prompt(
    *,
    repo_name: str,
    finding: "Finding",
    sibling_refs: list[str],
) -> str:
    """Render the per-candidate adversarial prompt via PackageLoader (Task 1 j2)."""
    env = Environment(
        loader=PackageLoader("repo_audit", "verification/prompts"),
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tpl = env.get_template("critic.md.j2")
    return tpl.render(
        repo_name=repo_name,
        finding={
            "rule_id": getattr(finding, "rule_id", "") or "",
            "file": getattr(finding, "file", "") or "",
            "line": getattr(finding, "line", "") if getattr(finding, "line", None) is not None else "",
            "dimension": getattr(finding, "dimension", "") or "",
            "severity": getattr(finding, "severity", "") or "",
            "source_tool": getattr(finding, "source_tool", "") or "",
            "evidence_type": getattr(finding, "evidence_type", "") or "",
            "snippet": getattr(getattr(finding, "evidence", None), "output_snippet", "") or "",
        },
        sibling_refs=sibling_refs,
    )


# --- run_critic_session — the bounded priority-queue loop (clone of session) -


async def _run_live_candidate(*, candidate_ref: str, options, prompt: str) -> int:
    """Run one candidate through a live ClaudeSDKClient. Returns tokens consumed.

    Clones the session.py token-tally + disconnect loop, scoped to ONE candidate
    (the critic reviews one finding per session). Never promotes a rung — the
    verdict is collected from the submit_verdict module state by the caller.
    """
    from claude_agent_sdk import AssistantMessage, ClaudeSDKClient, ResultMessage

    max_tokens = get_threshold("critic.max_tokens_per_scan")
    running = 0
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        async for msg in client.receive_messages():
            if isinstance(msg, AssistantMessage) and msg.usage:
                it = msg.usage.get("input_tokens", 0)
                ot = msg.usage.get("output_tokens", 0)
                running += (it if isinstance(it, int) else 0) + (
                    ot if isinstance(ot, int) else 0
                )
                if running >= max_tokens:
                    await client.disconnect()
                    break
            elif isinstance(msg, ResultMessage):
                break
    return running


async def run_critic_session(
    *,
    queue: "list[Finding]",
    repo_path: "Path | str | None",
    records: "list[VerificationRecord]",
    meta: "VerificationMeta",
    repo_name: str = "",
    client_factory: Callable | None = None,
    corroborated_findings: "list[Finding] | None" = None,
) -> "tuple[list[Verdict], VerificationMeta]":
    """Review the priority queue under separate token + wall-clock budgets.

    Clones ``agent/session.py``, narrowed for adversarial per-candidate review:

      * Budget bound (CRIT-5): at the TOP of each iteration, if
        ``running_tokens >= critic.max_tokens_per_scan`` OR elapsed wall-clock
        ``>= critic.max_wall_clock_seconds``, STOP — the remaining candidates go
        un-reviewed (honest partial; meta.critic_reviewed < meta.critic_total_queue).
      * Per-candidate isolation: each finding gets its own ``reset_critic_state``
        + (live) ClaudeSDKClient. The critic emits a Verdict ONLY; it never
        promotes a rung (the stage applies refuted verdicts).
      * Never-raise (D-17-06 / D-25): any per-candidate exception →
        ``except Exception: continue`` (that finding gets no verdict; the queue
        proceeds). ``run_critic_session`` ALWAYS returns ``(verdicts, meta)``.

    ``client_factory`` is the test seam (``mock_critic_client``): when provided,
    the loop uses it instead of a live ClaudeSDKClient so the budget/never-raise
    behavior is exercised without the SDK. Each per-candidate client exposes an
    async ``run_once()`` that applies the canned verdict (via the REAL
    ``submit_verdict`` handler, so the citation validator still runs).
    """
    verdicts: list[Verdict] = []
    meta.critic_total_queue = len(queue)
    all_refs = [build_finding_ref(f) for f in queue]

    # 17-04: resolve each QUEUED finding's per-candidate IDENTITY token. The queue
    # is a re-ordered SUBSET of the corroborated findings, so enumerate(queue) is
    # NOT the input index — the token must come from the finding's PAIRED record.
    # ``corroborated_findings`` is the post-corroboration finding list that
    # ``records`` is index-paired with (tiered_corroborate returns them aligned).
    # Build an exact object-identity map id(finding) -> record.candidate_token: two
    # fingerprint-colliding findings are DISTINCT objects → DISTINCT tokens, and a
    # queued finding is the SAME object build_priority_queue selected from the
    # corroborated set, so the token a verdict gets stamped with is exactly the one
    # the stage reads for that finding in _apply_verdicts. (No fingerprint matching
    # anywhere — identity is by object, the whole point of the fix.)
    _token_by_id: dict[int, int] = {}
    if corroborated_findings is not None and len(corroborated_findings) == len(records):
        for cf, rec in zip(corroborated_findings, records):
            _token_by_id[id(cf)] = rec.candidate_token

    def _token_for_finding(f) -> int:
        return _token_by_id.get(id(f), -1)

    max_tokens = get_threshold("critic.max_tokens_per_scan")
    max_wall = get_threshold("critic.max_wall_clock_seconds")
    start = time.perf_counter()
    running_tokens = 0

    server = build_critic_mcp_server() if client_factory is None else None

    for idx, finding in enumerate(queue):
        # Budget bound checked at the TOP of each iteration (honest partial).
        if running_tokens >= max_tokens or (time.perf_counter() - start) >= max_wall:
            break

        candidate_ref = all_refs[idx]
        candidate_token = _token_for_finding(finding)
        # Sibling fingerprints = the OTHER queued findings (duplicate angle).
        sibling_refs = [r for j, r in enumerate(all_refs) if j != idx]
        reset_critic_state(
            repo_path=repo_path,
            finding_set=list(queue),
            candidate_ref=candidate_ref,
            candidate_token=candidate_token,
        )

        try:
            if client_factory is not None:
                # Test path: the mock client applies the canned verdict.
                client = client_factory(candidate_ref=candidate_ref)
                async with client:
                    await client.run_once()
            else:
                prompt = _render_critic_prompt(
                    repo_name=repo_name, finding=finding, sibling_refs=sibling_refs
                )
                options = build_critic_options(
                    mcp_server=server, system_prompt=prompt
                )
                running_tokens += await _run_live_candidate(
                    candidate_ref=candidate_ref, options=options, prompt=prompt
                )
        except Exception:
            # Never-raise: this candidate gets no verdict; the queue proceeds.
            meta.critic_reviewed += 1
            meta.discarded_refutations.extend(get_discarded())
            continue

        meta.critic_reviewed += 1
        verdict = get_submitted_verdict()
        if verdict is not None:
            verdicts.append(verdict)
        meta.discarded_refutations.extend(get_discarded())

    return verdicts, meta


__all__ = [
    "Verdict",
    "VerdictPayload",
    "VerificationMeta",
    "submit_verdict",
    "get_repo_excerpt",
    "build_critic_mcp_server",
    "build_critic_options",
    "build_priority_queue",
    "run_critic_session",
    "_citation_is_valid",
    "reset_critic_state",
    "get_submitted_verdict",
    "get_discarded",
]
