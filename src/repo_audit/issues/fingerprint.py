"""Line-excluding finding fingerprint for ``repo-audit issues`` (Phase 19, Plan 19-02).

This is the DEDUP identity (CONTEXT decisions D-15 + D-14), and it is
deliberately DISTINCT from the human-readable display reference produced by the
finding-ref helper in ``verification.record``. That display reference includes
the source line number and is explicitly non-unique — it exists only to label a
finding for a human reading a result table (D-13). Using it as the dedup key
would be the collision named in 19-RESEARCH Pitfall 5: when unrelated code is
added or removed ABOVE a finding, the finding's line number shifts, the display
reference changes, and the dedup layer would file a false duplicate of an issue
that is already open for the very same problem.

So this fingerprint EXCLUDES the source line number entirely (D-15). Its
identity is a stable sha256 over the normalized, low-volatility parts of a
finding — the producing tool, the rule id, the repo-relative file path, and the
recommendation text (per 19-RESEARCH Assumption A1: ``Finding`` carries no
dedicated symbol/snippet field, so ``recommendation`` is the chosen stable
identity component). Two findings for the same problem at different source
positions therefore hash IDENTICALLY, which is exactly what keeps Plan 03's
dedup from re-filing on a line shift.

The fingerprint is embedded in an issue body as a hidden HTML comment marker
(D-14) so a later run can recover an open issue's fingerprints by scanning its
body, with no visible clutter for human readers.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath

from repo_audit.schema.finding import Finding

# D-14 — the hidden marker embedded at an issue body's tail. ``{}`` is the
# hex sha256 digest. A later run greps an open issue's body for this shape to
# recover the fingerprints it already represents (dedup, Plan 03).
MARKER = "<!-- repo-audit-fingerprint: {} -->"

# Recovers every embedded fingerprint digest from a body. Matches the MARKER
# shape tolerantly (any surrounding whitespace inside the comment).
_MARKER_RE = re.compile(r"<!--\s*repo-audit-fingerprint:\s*([0-9a-f]+)\s*-->")

# Field separator for the hashed identity join. A non-printable unit-separator
# byte cannot appear inside any of the normalized parts, so it cannot be used to
# forge a collision by sliding content across a boundary.
_SEP = "\x1f"


def _normalize_path(finding: Finding, repo_root: Path | None) -> str:
    """Repo-relative POSIX path for the finding's file, or '' when absent.

    When ``repo_root`` is given, the path is normalized repo-relative so an
    absolute and a repo-relative reference to the same logical file normalize
    identically. Falls back to the lexically-normalized POSIX text when the file
    lies outside ``repo_root`` or when no ``repo_root`` is supplied.

    IN-04: normalization is purely LEXICAL (``os.path.normpath`` / ``PurePosixPath``)
    — it does NOT touch the filesystem or resolve symlinks. ``Path.resolve()``
    would canonicalize symlinks and depend on the working checkout, so the SAME
    logical finding could fingerprint differently across machines/checkouts (a
    deleted-since file, a symlinked path), weakening cross-run dedup stability —
    the opposite of the fingerprint's stated goal. No filesystem fact is needed
    here: the input is already a repo-relative-or-absolute path string.
    """
    raw = getattr(finding, "file", None)
    if not raw:
        return ""
    norm = os.path.normpath(raw)
    if repo_root is not None:
        root_norm = os.path.normpath(str(repo_root))
        try:
            rel = PurePosixPath(Path(norm).as_posix()).relative_to(
                PurePosixPath(Path(root_norm).as_posix())
            )
            return rel.as_posix()
        except ValueError:
            return Path(norm).as_posix()
    return Path(norm).as_posix()


def build_fingerprint(finding: Finding, *, repo_root: Path | None = None) -> str:
    """Return the stable, line-excluded sha256 identity for ``finding``.

    Identity parts (normalized, ``\\x1f``-joined): producing tool (lowercased),
    rule id (lowercased), repo-relative POSIX file path, and a
    whitespace-collapsed recommendation. The source line number is NOT among
    them (D-15) — that is the whole point: identity must survive line drift.

    Args:
        finding: the Finding to fingerprint.
        repo_root: optional repo root; when given, the file path normalizes
            repo-relative so absolute/relative references to the same file
            collide. Omitted in pure-identity callers (the line-stability
            guarantee does not depend on it).
    """
    tool = (getattr(finding, "source_tool", "") or "").lower()
    rule = (getattr(finding, "rule_id", "") or "").lower()
    path = _normalize_path(finding, repo_root)
    # Whitespace-collapsed recommendation — the stable code-context surrogate
    # (Assumption A1). Collapsing runs of whitespace makes the identity robust
    # to reflowing/indent churn in the recommendation text.
    recommendation = " ".join((getattr(finding, "recommendation", "") or "").split())

    # WR-03: when BOTH rule_id and recommendation are empty (both default to ""),
    # the identity collapses to just (tool, path) — so two distinct confirmed
    # findings in the same file would hash identically and dedup would treat one
    # as a duplicate of the other. Fold in an extra stable discriminator in that
    # degenerate case only (kept conditional so the common, well-populated case
    # keeps its existing, line-stable identity): prefer ``source_collector``, and
    # fall back to a hash of the evidence ``output_snippet``.
    discriminator = ""
    if not rule and not recommendation:
        collector = (getattr(finding, "source_collector", "") or "").lower()
        if collector:
            discriminator = collector
        else:
            evidence = getattr(finding, "evidence", None)
            snippet = (getattr(evidence, "output_snippet", "") or "").strip()
            if snippet:
                discriminator = hashlib.sha256(
                    snippet.encode("utf-8")
                ).hexdigest()

    identity = _SEP.join((tool, rule, path, recommendation, discriminator))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


# Test-facing alias: the Wave-0 scaffold calls ``fingerprint.fingerprint(f)``
# with a single positional finding. Same callable, friendlier name at the
# module's public surface.
def fingerprint(finding: Finding, *, repo_root: Path | None = None) -> str:
    """Alias of :func:`build_fingerprint` (the scaffold's public call shape)."""
    return build_fingerprint(finding, repo_root=repo_root)


def build_rollup_fingerprint(member_fingerprints: list[str], *, dimension: str) -> str:
    """Synthetic, membership-aware identity for a per-dimension rollup (CR-01).

    The rollup's dedup identity is a sha256 over ``("rollup", dimension,
    *sorted(member_fingerprints))``. Two properties follow:

      * The ``"rollup"`` prefix guarantees it can NEVER collide with a solo /
        member fingerprint (which hash over ``(tool, rule, path, recommendation)``
        with no such prefix) — so an open issue carrying a single member's marker
        can never false-duplicate the whole rollup (the silent whole-dimension
        drop the original ``members[0]`` identity caused).
      * Sorting the member fingerprints makes the identity ORDER-STABLE, and
        folding in the full member set makes membership churn VISIBLE to dedup:
        adding/removing a confirmed finding changes the rollup's identity, so a
        rollup that gained new findings no longer hashes identically to an
        already-open one.
    """
    parts = ("rollup", dimension, *sorted(member_fingerprints))
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()


def embed_marker(body: str, fp: str) -> str:
    """Append the hidden D-14 fingerprint marker to a body's tail."""
    tail = MARKER.format(fp)
    if body and not body.endswith("\n"):
        body += "\n"
    return f"{body}{tail}\n"


def extract_fingerprints(body: str) -> set[str]:
    """Recover every embedded fingerprint digest from a body (dedup support)."""
    return set(_MARKER_RE.findall(body or ""))


__all__ = [
    "MARKER",
    "build_fingerprint",
    "build_rollup_fingerprint",
    "fingerprint",
    "embed_marker",
    "extract_fingerprints",
]
