"""Synthetic vulnerable-repo factory for the Phase 10 (SAST — Semgrep) live run.

``make_sast_vuln_repo(root)`` writes a tiny, SYNTHETIC repository under ``root``
that the Wave-3 ``-m integration`` live Semgrep run scans end-to-end. It is built
with stdlib (``pathlib``) only and does NOT git-init (the SAST collector reads
files; it does not walk git history).

What the repo contains and WHY:

* ``package.json`` — declares ``react`` + ``react-native`` deps so the stack
  detector classifies the repo as ``expo`` / ``react-native`` and the Wave-2
  ruleset table selects ``p/react`` (in addition to the OWASP pack).
* ``src/vuln.py`` — an OBVIOUS OS-command-injection
  (``subprocess.run("ls " + user_input, shell=True)``) so the live
  ``p/owasp-top-ten`` run has a real, deterministically-detected OWASP-A03
  (Injection) finding to map. ``shell=True`` on a string command is the
  ``python.lang.security.audit.subprocess-shell-true`` rule, which is in the
  current ``p/owasp-top-ten`` pack and carries an ``OWASP-A03:2021 - Injection``
  tag (the bare ``os.system(... + input)`` shape is NOT in the current pack —
  verified live during Plan 10-04).
* ``src/component.tsx`` — a benign React surface (no secret, no injection) so
  the React pack has something to parse without producing a guaranteed finding.
* ``.env`` — carries a SYNTHETIC ``EXPO_PUBLIC_SUPABASE_ANON_KEY`` (the PUBLIC
  anon key). The live run's ``p/secrets`` pass will surface it; the SAST-03 drop
  (Wave 2) must NOT report it as a leak — this is the live counterpart to the
  ``secrets_anon.sarif`` Result A.

All secret values are synthetic, obviously-fake JWTs (role-claim only, fake
signature). See ``PROVENANCE.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

# A synthetic, obviously-fake anon JWT (role=anon, fake signature). NOT a real
# key. Mirrors the value in secrets_anon.sarif Result A.
_SYNTHETIC_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJyb2xlIjoiYW5vbiIsImlzcyI6InN5bnRoZXRpYy1maXh0dXJlIiwiaWF0IjoxNzAwMDAwMDAwfQ."
    "FAKE_SYNTHETIC_ANON_SIGNATURE_DO_NOT_USE"
)

_PACKAGE_JSON = json.dumps(
    {
        "name": "sast-vuln-fixture",
        "version": "0.0.0",
        "private": True,
        "dependencies": {
            "react": "18.2.0",
            "react-native": "0.74.0",
            "expo": "51.0.0",
        },
    },
    indent=2,
)

# OBVIOUS OS-command-injection: user input concatenated into a shell command
# run with shell=True. OWASP-A03 (Injection) — the live p/owasp-top-ten run's
# `python.lang.security.audit.subprocess-shell-true` rule detects this and tags
# it OWASP-A03:2021 - Injection (verified live during Plan 10-04).
_VULN_PY = (
    "import subprocess\n"
    "import sys\n"
    "\n"
    "\n"
    "def list_dir(user_input: str) -> None:\n"
    '    """List a user-named path. INTENTIONALLY VULNERABLE (fixture).\n'
    "\n"
    "    Builds a shell command from unsanitized user input and runs it with\n"
    "    shell=True — command injection (OWASP-A03). This exists ONLY to give the\n"
    "    live Semgrep run a real, deterministic OWASP finding to map. Never ship\n"
    "    this shape.\n"
    '    """\n'
    '    subprocess.run("ls " + user_input, shell=True)\n'
    "\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    list_dir(sys.argv[1])\n"
)

# A benign React surface — no secret, no injection.
_COMPONENT_TSX = (
    "import React from 'react';\n"
    "\n"
    "type Props = { name: string };\n"
    "\n"
    "export function Greeting({ name }: Props): React.JSX.Element {\n"
    "  return <span>Hello, {name}</span>;\n"
    "}\n"
)

# Synthetic .env carrying ONLY the PUBLIC anon key (allowlisted; must not be
# reported as a leak by the SAST-03 drop).
_ENV = f"EXPO_PUBLIC_SUPABASE_URL=https://synthetic.example.supabase.co\nEXPO_PUBLIC_SUPABASE_ANON_KEY={_SYNTHETIC_ANON_KEY}\n"


def make_sast_vuln_repo(root: Path) -> Path:
    """Build a synthetic vulnerable Expo/RN repo under ``root``.

    Writes ``package.json``, ``src/vuln.py``, ``src/component.tsx`` and ``.env``.
    Returns the repo root (``root`` itself). Creates ``root`` if missing. Writes
    only under the caller-supplied ``root`` (T-10-W0-02). Does NOT git-init.

    Args:
        root: target directory (typically a pytest ``tmp_path`` subdir).

    Returns:
        The repo root path.
    """
    root = Path(root)
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)

    (root / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")
    (src / "vuln.py").write_text(_VULN_PY, encoding="utf-8")
    (src / "component.tsx").write_text(_COMPONENT_TSX, encoding="utf-8")
    (root / ".env").write_text(_ENV, encoding="utf-8")

    return root


__all__ = ["make_sast_vuln_repo"]
