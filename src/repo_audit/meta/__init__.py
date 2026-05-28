"""Helpers for scan metadata: repo slug, HEAD SHA, output paths."""
from repo_audit.meta.git import NotAGitRepo, UNCOMMITTED_MARKER, head_sha
from repo_audit.meta.git_status import diff_git_status, snapshot_git_status
from repo_audit.meta.paths import state_report_paths
from repo_audit.meta.slug import repo_slug

__all__ = [
    "head_sha",
    "NotAGitRepo",
    "UNCOMMITTED_MARKER",
    "state_report_paths",
    "repo_slug",
    "snapshot_git_status",
    "diff_git_status",
]
