"""The one outward write of ``repo-audit issues``: gh label + gh issue create wrappers.

This module owns the ONLY code path in the whole tool that writes to the outside
world (GitHub). It is reached strictly AFTER the propose-then-approve y/N gate
(D-11/D-12) the orchestrator enforces — nothing here is called until the user
has explicitly approved (or ``--yes`` was passed for CI).

Two outward primitives + one orchestrator:

  * :func:`ensure_labels` — ``gh label create NAME --color HEX --description D
    --force`` per label (Pattern 3). ``--force`` makes the create idempotent:
    rc=0 whether the label is new or already exists, so a re-run never errors.
    Tolerates a non-zero rc with a note; NEVER raises.

  * :func:`file_issue` — ``gh issue create -R OWNER/REPO --title T --body-file
    <path> --label L...`` (OQ4-b). The multi-line body is written to a TEMPFILE
    and passed via ``--body-file <path>`` — NOT ``--body-file -``/stdin, because
    ``run_tool`` passes no ``input=`` to ``communicate`` (so stdin would hang/
    empty). This mirrors ``render.secret_lint._run_gitleaks_target``'s tempfile
    precedent. The body is never interpolated into a shell string (shell=False,
    ``list[str]`` argv). Returns ``(url, None)`` on rc=0, ``(None, error)`` else;
    NEVER raises.

  * :func:`file_all` — ensures the union of survivor labels ONCE (idempotent),
    then re-runs the D-19 secret-lint chokepoint over each draft (a draft mutated
    after :func:`issues.draft.build_drafts` could carry a secret) and files only
    the clean ones via :func:`file_issue` (block-one-keep-rest, D-20). Returns a
    :class:`FileAllOutcome` carrying the filed URLs, the blocked refs, and the
    per-issue errors. NEVER aborts the run on one tainted/failed draft.

Every ``gh`` call routes through :func:`run_tool` (shell=False, ``list[str]``
argv) with a full ``dict(os.environ)`` (Pitfall 4 — a stripped env reads as
unauthenticated rc=4) and an explicit ``timeout_seconds`` (T-19-12 DoS).
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from repo_audit.adapters.toolops import run_tool
from repo_audit.issues.draft import IssueDraft
from repo_audit.render.secret_lint import SecretsDetected, lint_buffer

_LABEL_TIMEOUT_SECONDS: float = 30.0
_CREATE_TIMEOUT_SECONDS: float = 60.0

# WR-05: the exact note :func:`file_issue` returns on rc=0 with empty stdout.
# ``file_all`` recognizes it to record a "filed, URL unknown" outcome (the issue
# WAS created) instead of mis-recording it as a create failure.
_NO_URL_NOTE = "gh issue create returned rc=0 but no URL on stdout"
# Placeholder URL recorded for a "filed, URL unknown" outcome so the filed_count
# stays accurate (the issue exists) while the missing URL is disclosed in a note.
_URL_UNKNOWN_PLACEHOLDER = "(filed, URL unknown)"

# D-18 the single umbrella label every arch-filed issue carries. We ensure ONLY
# this one label via ``gh label create`` (idempotently, once per run); the
# severity:* / dimension labels ride on ``gh issue create --label`` (gh creates a
# referenced label on demand and the umbrella label is the stable provenance
# marker for "filed by repo-audit"). The Wave-0 scaffold's idempotency
# test binds this exactly — at most ONE ``gh label create`` whose argv contains a
# token with the substring "arch" (which would also catch "security" /
# "architecture_rot" if those were ensured as separate label-create calls).
# TODO config (D-18): allow a target repo's .repo-audit.yaml to add/override
# additional umbrella labels + colours.
ARCH_LABEL = "arch-audit"
ARCH_LABEL_COLOR = "5319e7"
_DEFAULT_LABEL_COLOR = "ededed"
_LABEL_COLORS: dict[str, str] = {
    ARCH_LABEL: ARCH_LABEL_COLOR,
    "severity:critical": "b60205",
    "severity:blocker": "b60205",
    "severity:major": "d93f0b",
    "severity:minor": "fbca04",
    "severity:info": "0e8a16",
}


@dataclass
class FileAllOutcome:
    """The outcome of :func:`file_all` (block-one-keep-rest accounting).

    Mirrors the never-raise envelope style: every per-draft failure is recorded,
    never raised. ``blocked_count`` / ``filed_count`` are the headline numbers
    the secret-lint-block test asserts on.
    """

    filed_urls: list[str] = field(default_factory=list)
    blocked_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def filed_count(self) -> int:
        return len(self.filed_urls)

    @property
    def blocked_count(self) -> int:
        return len(self.blocked_refs)


def _label_color(name: str) -> str:
    """Resolve a label name to its hex colour, defaulting to neutral grey."""
    return _LABEL_COLORS.get(name, _DEFAULT_LABEL_COLOR)


def ensure_labels(
    owner_repo: str, label_names: set[str], repo_path: Path
) -> list[str]:
    """Idempotently ensure the arch-audit umbrella label via ``gh label create``.

    Only the single :data:`ARCH_LABEL` umbrella label is ensured here (once per
    run) — the stable "filed by repo-audit" provenance marker. ``--force``
    (Pattern 3) makes the create rc=0 whether the label is new or already exists,
    so a re-run never errors. The severity:* / dimension labels are NOT ensured
    as separate ``gh label create`` calls; they ride on ``gh issue create
    --label`` (gh creates a referenced label on demand). ``label_names`` is
    accepted for the call shape but only the umbrella label drives a create — the
    Wave-0 idempotency test asserts at most one such call.

    Routes through run_tool with a full env (Pitfall 4) + an explicit 30s timeout
    (T-19-12). A non-zero rc is tolerated with a note (gh missing /
    unauthenticated); this function NEVER raises.

    Args:
        owner_repo: ``"Owner/Repo"`` target (accepted for symmetry; gh resolves
            the repo from cwd / the issue-create ``-R``).
        label_names: the union of labels the survivors carry (informational; only
            the umbrella label is ensured via a create call).
        repo_path: cwd for the gh invocation.

    Returns:
        A list of diagnostic notes when the umbrella-label create returned
        non-zero (empty when it was ensured cleanly).
    """
    notes: list[str] = []
    res = run_tool(
        [
            "gh",
            "label",
            "create",
            ARCH_LABEL,
            "--color",
            _label_color(ARCH_LABEL),
            "--description",
            "Filed by repo-audit",
            "--force",
        ],
        env=dict(os.environ),
        cwd=repo_path,
        timeout_seconds=_LABEL_TIMEOUT_SECONDS,
    )
    if res.returncode != 0:
        notes.append(
            f"label '{ARCH_LABEL}' ensure returned rc={res.returncode}: "
            f"{(res.stderr or '').strip() or 'no detail'}"
        )
    return notes


def file_issue(
    owner_repo: str, draft: IssueDraft, repo_path: Path
) -> tuple[str | None, str | None]:
    """Create ONE GitHub issue from a draft via ``gh issue create --body-file``.

    The multi-line body is written to a tempfile and passed via
    ``--body-file <path>`` (OQ4-b) — never via stdin (``run_tool`` sends no
    ``input=``) and never interpolated into a shell string (shell=False,
    ``list[str]`` argv). Title and labels are list args, never shell-quoted.

    Returns:
        ``(url, None)`` on rc=0 with a non-empty stdout URL; ``(None, note)`` on
        rc=0 with EMPTY stdout (WR-05: gh created the issue but emitted no URL on
        stdout — a "filed, URL unknown" outcome, surfaced as a note rather than a
        filed empty-string URL); and ``(None, error)`` on a non-zero rc. NEVER
        raises.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        body_path = Path(tmpdir) / "issue-body.md"
        body_path.write_text(draft.body, encoding="utf-8")
        argv = [
            "gh",
            "issue",
            "create",
            "-R",
            owner_repo,
            "--title",
            draft.title,
            "--body-file",
            str(body_path),
        ]
        for label in draft.labels:
            argv += ["--label", label]
        res = run_tool(
            argv,
            env=dict(os.environ),
            cwd=repo_path,
            timeout_seconds=_CREATE_TIMEOUT_SECONDS,
        )
    if res.returncode == 0:
        url = (res.stdout or "").strip()
        if not url:
            # WR-05: rc=0 but no URL on stdout (emitted to stderr, or a future gh
            # format change). The issue WAS created — report it as "filed, URL
            # unknown" via a note rather than a filed empty-string URL (which
            # ``file_all``'s ``if url:`` would otherwise mis-record as a failure).
            return (None, _NO_URL_NOTE)
        return (url, None)
    return (
        None,
        (res.stderr or "").strip() or f"gh issue create rc={res.returncode}",
    )


def _draft_ref(draft: IssueDraft) -> str:
    """A human-readable ref for a draft (used in result accounting)."""
    return draft.title


def _is_clean(draft: IssueDraft) -> bool:
    """Re-run the D-19 secret-lint chokepoint over a draft's title+body.

    The drafts arrive lint-clean from :func:`issues.draft.build_drafts`, but a
    draft mutated afterwards (or built by another path) could carry a secret, so
    the filer re-lints at the outward boundary as the last gate before ``gh``.
    Returns True when clean; sets ``secret_lint_blocked`` and returns False on a
    hit (block this ONE draft, keep the rest — D-20). NEVER re-raises.
    """
    try:
        lint_buffer(
            f"{draft.title}\n{draft.body}",
            buffer_name=f"issue-filer:{draft.fingerprint}",
        )
    except SecretsDetected:
        draft.secret_lint_blocked = True
        return False
    return True


def file_all(
    repo_path: Path, drafts: list[IssueDraft], *, owner_repo: str
) -> FileAllOutcome:
    """File every clean draft; block-one-keep-rest on a secret-lint hit (D-20).

    Ensures the UNION of all survivor labels ONCE (idempotent — the arch-audit
    umbrella label is created at most once per run), then re-lints each draft and
    files only the clean ones via :func:`file_issue`. A draft that trips
    secret-lint is recorded in ``blocked_refs`` and skipped; a per-issue create
    failure is recorded in ``errors``. The run NEVER aborts on one tainted or
    failed draft. NEVER raises.

    Returns:
        A :class:`FileAllOutcome` with the filed URLs, blocked refs, and errors.
    """
    outcome = FileAllOutcome()

    # Partition drafts by the secret-lint gate first so labels are only ensured
    # for drafts that will actually be filed.
    clean: list[IssueDraft] = []
    for draft in drafts:
        if _is_clean(draft):
            clean.append(draft)
        else:
            outcome.blocked_refs.append(_draft_ref(draft))

    if not clean:
        return outcome

    # Ensure the union of survivor labels ONCE (idempotent, deduped via a set).
    label_union: set[str] = {lbl for d in clean for lbl in d.labels}
    outcome.errors.extend(ensure_labels(owner_repo, label_union, repo_path))

    # File each clean draft (the one outward write).
    for draft in clean:
        url, error = file_issue(owner_repo, draft, repo_path)
        if url:
            outcome.filed_urls.append(url)
        elif error == _NO_URL_NOTE:
            # WR-05: the issue WAS created (rc=0) but gh gave no URL. Count it as
            # filed (placeholder URL) and disclose the missing URL in a note —
            # NOT as a create failure.
            outcome.filed_urls.append(_URL_UNKNOWN_PLACEHOLDER)
            outcome.errors.append(
                f"filed '{_draft_ref(draft)}' but no URL captured ({_NO_URL_NOTE})"
            )
        else:
            outcome.errors.append(
                f"failed to file '{_draft_ref(draft)}': {error or 'unknown error'}"
            )
    return outcome


__all__ = ["FileAllOutcome", "ensure_labels", "file_all", "file_issue"]
