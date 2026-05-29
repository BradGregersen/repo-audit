"""Markdown + JSON sidecar renderer for ScanReport."""
from repo_audit.render.faithfulness import (
    build_allowed_numbers,
    check_faithfulness,
    load_faithfulness_allowlist,
    split_sentences,
    walk_parsed_value,
)
from repo_audit.render.renderer import render_and_write, render_markdown

__all__ = [
    "render_and_write",
    "render_markdown",
    "build_allowed_numbers",
    "check_faithfulness",
    "load_faithfulness_allowlist",
    "split_sentences",
    "walk_parsed_value",
]
