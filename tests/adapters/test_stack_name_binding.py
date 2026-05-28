"""Open question #1 resolution: pin the TypeScript stack literal.

Phase 1's detector emits StackProfile.stack='typescript-node' for any
repo with tsconfig.json. Every Phase 3 @register_adapter call and every
adapter.yaml `name:` field MUST use this exact string. A mismatch
silently disables the adapter (orchestrator looks up by string equality).
"""
from repo_audit.detect.detector import detect_stacks
from repo_audit.detect.rules import MANIFEST_RULES


def test_manifest_rules_contains_typescript_node():
    names = [r.name for r in MANIFEST_RULES]
    assert "typescript-node" in names, (
        f"Phase 3 plans pin 'typescript-node'; MANIFEST_RULES has {names}. "
        "Update the plan literals or fix the detector."
    )


def test_detector_emits_typescript_node_literal(polyglot_repo):
    result = detect_stacks(polyglot_repo)
    emitted = [p.stack for p in result.stacks]
    assert "typescript-node" in emitted, (
        f"Phase 3 @register_adapter('typescript-node') will never fire — "
        f"detector emits {emitted}."
    )
