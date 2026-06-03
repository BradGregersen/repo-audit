"""D-11-08 — detekt noise floor (rule-id-prefix drop + severity floor).

detekt over a real Kotlin/Android repo emits a large volume of pure-style and
pure-formatting findings (``detekt.style.MagicNumber``,
``detekt.formatting.Indentation``, …) that are NOT actionable audit signal —
they are noise (11-RESEARCH Pitfall 7). :func:`apply_detekt_noise_floor` drops
them BEFORE any finding reaches the report by keying on the ruleId PREFIX, and
also drops findings strictly below a severity floor (default: ``minor``).

The drop is PREFIX-keyed by design: a maintainer who reworks the floor to key on
message text or file path (the Pitfall-7 wrong approach) trips the Wave-0
contract test ``test_detekt_noise.py``. The keep families
(``detekt.potential-bugs.*``, ``detekt.complexity.*``, ``detekt.exceptions.*``,
``detekt.coroutines.*``, ``detekt.empty-blocks.*``) are the bug/complexity rules
that carry real signal; they are kept simply by NOT matching a drop prefix.

Both halves are deterministic, order-preserving, and OVERRIDABLE: a
``.repo-audit.yaml`` ``kotlin`` block (passed as the ``override`` dict) can
REPLACE the drop-prefix tuple (key ``"drop_ruleset_prefixes"``) and/or the
severity floor (key ``"severity_floor"``). Following the scoped-config posture of
``sast/noise.py`` there is NO central config loader — the caller hands the
resolved dict in here. The override only supplies scalars (a list of string
prefixes + a string floor); it never executes code.
"""
from __future__ import annotations

from typing import Any

from repo_audit.schema.finding import Finding

# Default ruleId prefixes to DROP (D-11-08, 11-RESEARCH Pitfall 7). detekt
# ruleIds have the shape ``detekt.{ruleset}.{RuleName}`` — the ``style`` and
# ``formatting`` rulesets are the pure-style/formatting families with no audit
# signal. An override REPLACES this tuple via key ``"drop_ruleset_prefixes"``.
DROP_RULESET_PREFIXES: tuple[str, ...] = ("detekt.style.", "detekt.formatting.")

# Default severity floor: drop findings STRICTLY below this rung. "minor" means
# 'info' is dropped, 'minor' and above are kept. Mirrors sast/noise.py.
DEFAULT_SEVERITY_FLOOR: str = "minor"

# Severity rungs low -> high (schema/enums.Severity). Used for the floor compare.
# Copied from sast/noise.py so the two noise floors stay structurally identical.
_RANK: dict[str, int] = {
    "info": 0,
    "minor": 1,
    "major": 2,
    "critical": 3,
    "blocker": 4,
}


def apply_detekt_noise_floor(
    findings: list[Finding],
    *,
    override: dict[str, Any] | None = None,
) -> list[Finding]:
    """Drop ``detekt.style.*``/``detekt.formatting.*`` AND sub-floor findings.

    Deterministic and order-preserving: identical input yields an identical kept
    subset, in input order. Resolves the drop-prefix tuple + severity floor from
    ``override`` at CALL time (the scoped ``.repo-audit.yaml`` ``kotlin``
    block dict), defaulting to :data:`DROP_RULESET_PREFIXES` /
    :data:`DEFAULT_SEVERITY_FLOOR` when absent — so the floor is overridable
    without a central config system.

    Args:
        findings: the candidate findings (e.g. from ``sarif_to_findings``).
        override: an optional ``kotlin``-block dict. Recognized keys:
            ``"drop_ruleset_prefixes"`` (``list[str]`` of ruleId prefixes that
            REPLACES the defaults) and ``"severity_floor"`` (a Severity string
            that REPLACES the default floor). Unknown keys are ignored.

    Returns:
        The kept findings, in input order. A finding is dropped when its
        ``rule_id`` starts with any drop prefix OR its severity ranks strictly
        below the floor. A finding with no ``rule_id`` is never prefix-dropped
        (it cannot match a ruleset prefix) but is still subject to the floor.
    """
    override = override or {}
    prefixes_raw = override.get("drop_ruleset_prefixes")
    prefixes: tuple[str, ...] = (
        tuple(prefixes_raw) if prefixes_raw is not None else DROP_RULESET_PREFIXES
    )
    floor = override.get("severity_floor") or DEFAULT_SEVERITY_FLOOR
    floor_rank = _RANK.get(floor, _RANK[DEFAULT_SEVERITY_FLOOR])

    kept: list[Finding] = []
    for finding in findings:
        rule_id = finding.rule_id or ""
        if any(rule_id.startswith(prefix) for prefix in prefixes):
            continue
        if _RANK.get(finding.severity, 0) < floor_rank:
            continue
        kept.append(finding)
    return kept


__all__ = [
    "apply_detekt_noise_floor",
    "DROP_RULESET_PREFIXES",
    "DEFAULT_SEVERITY_FLOOR",
]
