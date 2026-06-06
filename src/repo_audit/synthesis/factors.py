"""Ordinal factor tables + the exploitability / blast-radius / locus helpers.

LOCKED shape (D-18-01/04/05): every factor normalizes to (0, 1]; the lowest LIVE
ordinal is a POSITIVE FLOOR (>= 0.10, Pitfall 2) — a genuine 0 is reserved for
"not applicable", which never occurs on a live finding. Reachability is RAISE-ONLY
tri-state (True boosts; None/False are neutral — downgrade-safe, D-18-04/SAFE-01:
NEVER lowers, NEVER changes evidence_type). The composite is the multiplicative
product of the four factors, so a floor on ANY axis suppresses the whole score.

[ASSUMED] — the specific MAGNITUDES below are a defensible first proposal derived
from the locked factor definitions + the existing ``_SEVERITY_RANK`` order
(18-RESEARCH §Code Examples). They are TUNING, not contract: a bad constant
misranks a finding but cannot break determinism, the no-pad invariant, or the
positive-floor / multiplicative / raise-only guarantees. Surface to discuss-phase
for a one-pass sanity check; the SHAPE is locked.
"""
from __future__ import annotations

# Positive floor for every live ordinal (Pitfall 2). 0 is reserved for N/A.
FLOOR: float = 0.10

# severity — mirrors _SEVERITY_RANK order, mapped to descending weights.
SEVERITY_WEIGHT: dict[str, float] = {
    "blocker": 1.00,
    "critical": 0.85,
    "major": 0.55,
    "minor": 0.30,
    "info": 0.12,
}

# confidence — confirmed > corroborated; candidates are body-only (D-18-07) but
# still scored. high/medium are pre-verification adapter rungs.
CONFIDENCE_WEIGHT: dict[str, float] = {
    "confirmed": 1.00,
    "corroborated": 0.80,
    "high": 0.55,
    "medium": 0.40,
    "candidate": 0.25,
}

# evidence_type component of exploitability (D-18-04: runtime > static > heuristic).
# 'failed'/'unavailable' → not-applicable floor band.
EVIDENCE_EXPLOIT: dict[str, float] = {
    "runtime": 1.00,
    "static": 0.60,
    "heuristic": 0.40,
    "unavailable": 0.20,
    "failed": 0.20,
}

# dimension exploitability class (D-18-04: injection/secret/RLS/auth inherently
# more exploitable than doc-presence/TODO). Mapped to the 7 enums.Dimension values.
DIM_EXPLOIT: dict[str, float] = {
    "security": 1.00,
    "correctness": 0.65,
    "test_integrity": 0.45,
    "architecture_rot": 0.40,
    "observability": 0.35,
    "process": 0.30,
    "quality": 0.30,
}

# dimension blast-radius class (D-18-05: secret/RLS/auth/supply-chain = wide).
DIM_BLAST: dict[str, float] = {
    "security": 1.00,
    "correctness": 0.60,
    "architecture_rot": 0.55,
    "observability": 0.40,
    "test_integrity": 0.35,
    "process": 0.30,
    "quality": 0.30,
}


def locus_class(file: str | None) -> float:
    """File-locus class (D-18-05): config/CI/infra/auth paths = repo-wide;
    test/fixture/example/docs = contained. Path-substring rules (deterministic).
    Always >= FLOOR."""
    if not file:
        return 0.55  # unknown locus → mid
    p = file.lower()
    if any(
        s in p
        for s in (
            "/test",
            "__tests__",
            "/fixture",
            "/example",
            "/mock",
            "/docs/",
            ".test.",
            ".spec.",
        )
    ):
        return max(0.30, FLOOR)  # contained
    if any(
        s in p
        for s in (
            ".github/workflows",
            "dockerfile",
            "/infra",
            "/.ci",
            "terraform",
            "/auth",
            "/config",
            ".env",
        )
    ):
        return 1.00  # repo-wide
    return 0.60  # ordinary source


def exploitability(
    evidence_type: str, reachable: bool | None, dim: str
) -> float:
    """Derived exploitability ORDINAL in (0, 1]. NEVER mutates ``evidence_type``
    (no static→runtime promotion — SAFE-01/VER-05); reachability is RAISE-ONLY
    tri-state (True nudges UP toward 1; None/False neutral, never lower). Floored."""
    base = EVIDENCE_EXPLOIT.get(evidence_type, 0.20) * DIM_EXPLOIT.get(dim, 0.30)
    # Phase-17 reachability is RAISE-ONLY (downgrade-safe, D-18-04 / SAFE-01).
    if reachable is True:
        base = base + (1.0 - base) * 0.25  # nudge up toward 1, never down
    return max(base, FLOOR)  # positive floor (Pitfall 2)


def blast_radius(dim: str, file: str | None) -> float:
    """Blast-radius ordinal = dimension blast class × file-locus class, floored."""
    return max(DIM_BLAST.get(dim, 0.30) * locus_class(file), FLOOR)


__all__ = [
    "FLOOR",
    "SEVERITY_WEIGHT",
    "CONFIDENCE_WEIGHT",
    "EVIDENCE_EXPLOIT",
    "DIM_EXPLOIT",
    "DIM_BLAST",
    "locus_class",
    "exploitability",
    "blast_radius",
]
