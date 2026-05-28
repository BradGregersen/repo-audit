"""Stack detector — fingerprints a repo from its manifest files.

Task 1 of Plan 01-03 ships rules.py and walker.py.
Task 2 adds detector.py; this `__init__.py` is then updated to re-export
`detect_stacks`.
"""
from repo_audit.detect.rules import MANIFEST_RULES, StackRule
from repo_audit.detect.walker import walk_for_manifests

__all__ = ["MANIFEST_RULES", "StackRule", "walk_for_manifests"]
