"""Stack detector — fingerprints a repo from its manifest files."""
from repo_audit.detect.detector import detect_stacks
from repo_audit.detect.rules import MANIFEST_RULES, StackRule
from repo_audit.detect.walker import walk_for_manifests

__all__ = ["detect_stacks", "MANIFEST_RULES", "StackRule", "walk_for_manifests"]
