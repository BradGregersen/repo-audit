"""Jinja2 custom filters for the state-report template.

severity_emoji -- vocabulary fixed in one place (not in the template)
provenance     -- REP-02 source tag (Phase 1 emits 'tool' only)
evidence_verb  -- D-17 fixed verb templates per evidence_type
"""
from __future__ import annotations


_SEVERITY_EMOJI = {
    "blocker": "\U0001F6AB",   # forbidden sign
    "critical": "\U0001F534",  # red circle
    "major": "\U0001F7E0",     # orange circle
    "minor": "\U0001F7E1",     # yellow circle
    "info": "ℹ️",    # information source
}


_EVIDENCE_VERB = {
    # D-17: fixed verb templates -- agents and collectors cannot override.
    "static": "The source declares",
    "runtime": "The test exercised",
    "heuristic": "A heuristic match suggested",
    "unavailable": "This check could not run because",
}


def severity_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity, "•")  # bullet


def provenance(source: str) -> str:
    """REP-02 provenance marker. Phase 1 only emits 'tool'; Phase 4 adds 'AI judgment'."""
    if source == "tool":
        return "_(source: tool)_"
    if source == "AI judgment":
        return "_(source: AI judgment)_"
    return f"_(source: {source})_"


def evidence_verb(evidence_type: str) -> str:
    return _EVIDENCE_VERB.get(evidence_type, "An unknown source reports")
