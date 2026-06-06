"""The ``repo-audit issues`` result envelope + D-13 summary render (Phase 19, Plan 19-04).

``IssuesResult`` is the never-raise outcome envelope the ``run_issues``
orchestrator returns and the thin ``repo-audit issues`` CLI command surfaces — the
direct analogue of ``orchestration.scan_runner.ScanResult`` /
``adapters.sca.osv.OsvResult``: every failure mode (no sidecar, gh unavailable,
wrong-repo guard, aborted gate, per-issue create failure) is folded into an
``rc`` + ``notes`` rather than an exception crossing the boundary.

``summary()`` renders the CONTEXT decision D-13 post-filing result report:

    {N} filed                  (with the new issue URLs)
    {M} skipped as duplicate   (with the already-open issue links)
    {K} blocked by secret-lint (with the finding refs that were dropped)

The CLI echoes this verbatim after the gate resolves (filed on ``y``,
nothing-filed counts on ``n``/abort/nothing-to-file).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IssuesResult:
    """Never-raise outcome of an ``repo-audit issues`` run (mirrors ScanResult/OsvResult).

    Attributes:
        rc: process exit code. ``0`` = success (including nothing-to-file and the
            aborted-gate case — declining the gate is a valid, non-error outcome);
            ``4`` = gh unavailable / unauthenticated / wrong-repo guard;
            ``5`` = no usable sidecar (run ``repo-audit scan`` first, D-02).
        filed: URLs of the issues actually created (the one outward write, D-13).
        skipped_duplicate: ``(finding_ref, existing_issue_url)`` pairs for drafts
            whose fingerprint matched an already-open issue (D-16).
        blocked_by_secret_lint: finding refs / titles whose draft tripped the
            secret-lint chokepoint and was dropped (D-19/D-20) — never filed.
        notes: human-readable diagnostic lines (no-sidecar reason, staleness
            warning, gh failure, per-issue create error, abort note).
    """

    rc: int = 0
    filed: list[str] = field(default_factory=list)
    skipped_duplicate: list[tuple[str, str]] = field(default_factory=list)
    blocked_by_secret_lint: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Render the D-13 post-filing result report as a multi-line string."""
        lines: list[str] = []

        # N filed (with URLs).
        lines.append(f"{len(self.filed)} filed")
        for url in self.filed:
            lines.append(f"  - {url}")

        # M skipped as duplicate (with the already-open issue links).
        lines.append(f"{len(self.skipped_duplicate)} skipped as duplicate")
        for ref, existing_url in self.skipped_duplicate:
            lines.append(f"  - {ref} -> {existing_url}")

        # K blocked by secret-lint (with finding refs).
        lines.append(f"{len(self.blocked_by_secret_lint)} blocked by secret-lint")
        for ref in self.blocked_by_secret_lint:
            lines.append(f"  - {ref}")

        # Any diagnostic notes (no-sidecar reason, staleness, abort, gh failure).
        for note in self.notes:
            lines.append(note)

        return "\n".join(lines)


__all__ = ["IssuesResult"]
