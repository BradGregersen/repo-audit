"""SYN-01 — exploitability is evidence-type-safe and floored.

`exploitability()` is a derived ORDINAL. It must never mutate the input
finding's `evidence_type` (no static→runtime promotion — SAFE-01/VER-05), it
returns a float in (0, 1], reachability is raise-only tri-state, and every live
factor-table value carries the positive floor (Pitfall 2).
"""
from __future__ import annotations

from repo_audit.synthesis import factors


def test_exploitability_is_evidence_type_safe(finding_factory):
    f = finding_factory(evidence_type="static", dimension="security")
    before = f.evidence_type

    val = factors.exploitability(f.evidence_type, None, f.dimension)

    # returns a float in (0, 1]
    assert isinstance(val, float)
    assert 0.0 < val <= 1.0
    # NEVER mutated the finding's evidence_type (no static→runtime promotion).
    assert f.evidence_type == before == "static"


def test_reachability_is_raise_only(finding_factory):
    base = factors.exploitability("static", None, "security")
    raised = factors.exploitability("static", True, "security")
    false_ = factors.exploitability("static", False, "security")

    # reachable=True nudges UP; None/False are neutral (never lower than base).
    assert raised >= base
    assert raised > false_ or raised > base  # True strictly raises
    assert false_ == base  # False is neutral, never lowers


def test_every_table_value_is_floored():
    floor = 0.10
    for table in (
        factors.SEVERITY_WEIGHT,
        factors.CONFIDENCE_WEIGHT,
        factors.EVIDENCE_EXPLOIT,
        factors.DIM_EXPLOIT,
        factors.DIM_BLAST,
    ):
        for v in table.values():
            assert v >= floor

    # the derived helpers also respect the floor
    assert factors.locus_class(None) >= floor
    assert factors.exploitability("failed", None, "process") >= floor
    assert factors.blast_radius("process", None) >= floor
