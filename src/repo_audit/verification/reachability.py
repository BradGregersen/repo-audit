"""Deterministic grep/AST import-presence reachability signal (greenfield, A4).

``check_reachable(finding, repo_path) -> bool | None`` produces a TRI-STATE
signal about whether a finding's target symbol/token is actually present in the
repo source:

    True  — the symbol/token IS present (for ``.py``: imported or referenced via
            an ``ast`` import-walk; for other stacks: the token appears in the
            target file).
    False — the symbol/token is absent.
    None  — not checked: no resolvable symbol target, unknown/unreadable file,
            or ANY error. ``None`` is the downgrade-safe "unknown".

HARD CONTRACT (D-17-03, SAFE-01):
    A POSITIVE result is an independent 2nd corroborating signal (1 tool +
    reachable = corroborated). A NEGATIVE or UNKNOWN result NEVER deletes and
    NEVER deterministically demotes a finding — asserting "unreachable ⇒ safe"
    would be the SAFE-01 static-vs-runtime overclaim. This function's ONLY job is
    to return the tri-state; the caller decides corroboration, and only on True.

SCOPE (A4 / RESEARCH): grep/AST IMPORT-PRESENCE ONLY. No taint, no dataflow.

NEVER-RAISES: every I/O path is wrapped; any failure returns ``None``. The
function cannot hang (it reads at most one bounded target file) and cannot crash
``run_verification`` (D-25).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding

# Cap on the bytes read from a single target file — protects against a hostile
# huge file (T-17-01-03). Generous enough for any real source file.
_MAX_FILE_BYTES: int = 4_000_000


def _resolve_symbol(finding: "Finding") -> str | None:
    """The symbol/token whose presence we check.

    Prefer an explicit ``evidence.parsed_value['symbol']`` (the reachability
    target a collector annotates); fall back to a non-empty ``rule_id``. Returns
    None when neither yields a usable target (→ caller returns None, never a
    deletion signal).
    """
    try:
        parsed = getattr(finding.evidence, "parsed_value", {}) or {}
        symbol = parsed.get("symbol")
        if isinstance(symbol, str) and symbol.strip():
            return symbol.strip()
    except Exception:
        return None
    rule_id = getattr(finding, "rule_id", "") or ""
    rule_id = rule_id.strip()
    return rule_id or None


def _python_symbol_present(source: str, symbol: str) -> bool | None:
    """AST import-walk: is ``symbol`` imported or referenced by name in ``source``?

    Returns True/False, or None if the source cannot be parsed (syntax error,
    non-UTF8 already decoded upstream). None keeps the signal downgrade-safe.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None

    for node in ast.walk(tree):
        # `import symbol` / `import pkg as symbol`
        if isinstance(node, ast.Import):
            for alias in node.names:
                if symbol in (alias.name, alias.asname):
                    return True
                # `import a.b.c` — match the leaf or any path segment.
                if symbol in alias.name.split("."):
                    return True
        # `from x import symbol` / `from x import y as symbol`
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if symbol in (alias.name, alias.asname):
                    return True
        # bare name reference (e.g. the symbol is used/defined in this module)
        elif isinstance(node, ast.Name) and node.id == symbol:
            return True
        elif isinstance(node, ast.Attribute) and node.attr == symbol:
            return True
        elif isinstance(node, ast.FunctionDef) and node.name == symbol:
            return True
        elif isinstance(node, ast.AsyncFunctionDef) and node.name == symbol:
            return True
        elif isinstance(node, ast.ClassDef) and node.name == symbol:
            return True
    return False


def check_reachable(finding: "Finding", repo_path: str | Path) -> bool | None:
    """Tri-state reachability signal for ``finding`` within ``repo_path``.

    See the module docstring for the full contract. Returns True/False/None and
    NEVER raises.
    """
    try:
        symbol = _resolve_symbol(finding)
        if symbol is None:
            return None

        rel = getattr(finding, "file", None)
        if not rel:
            return None

        root = Path(repo_path)
        target = root / rel
        if not target.is_file():
            return None

        # Bounded read; replace undecodable bytes (mirrors toolops._decode).
        try:
            data = target.read_bytes()[:_MAX_FILE_BYTES]
            source = data.decode("utf-8", errors="replace")
        except OSError:
            return None

        if target.suffix == ".py":
            result = _python_symbol_present(source, symbol)
            # An unparseable Python file falls back to a plain token presence
            # check rather than asserting absence (downgrade-safe).
            if result is None:
                return symbol in source
            return result

        # Non-Python stacks: plain token presence in the single target file
        # (grep-style import-presence, A4). Bounded by the single file → cannot
        # hang; any error already folded into None above.
        return symbol in source
    except Exception:
        # Any unanticipated failure → unknown, never a deletion/demotion signal.
        return None


__all__ = ["check_reachable"]
