"""Synthetic Expo->Android repo factory for Phase 9 (Mobile Pentest) tests.

``make_expo_android_repo(root)`` writes a minimal but realistic Expo/React-Native
tree under the caller-supplied ``root`` (a pytest ``tmp_path``) and returns it.
The tree deliberately seeds the exact secret-leak surfaces the Tier-2
bundled-secrets pass (Plan 02) and the mobsfscan integration run (Plan 01) must
exercise (09-RESEARCH § Architecture Pattern 2 — "Where secrets actually leak in
an Expo bundle"):

  * ``app.config.js``  — a hardcoded ``service_role`` JWT in the ``extra`` block
    (the CATASTROPHIC case the Tier-2 pass MUST flag).
  * ``.env``           — ``EXPO_PUBLIC_SUPABASE_ANON_KEY=<anon JWT>`` (the public
    key the Tier-2 pass must NEVER flag — anon-allowlist guard).
  * ``eas.json``       — a ``build.production.env`` block with one benign var and
    one ``sb_secret_<random>`` value (a secret-prefixed key — MUST be flagged).
  * ``android/.../strings.xml`` — a native-injected ``api_key`` (mobsfscan
    Tier-1 territory; present so this fixture doubles for an integration run).
  * ``app/screens/Login.tsx`` — client TS source under ``app/`` (so the
    footguns-style client walk has a file) kept deliberately SECRET-FREE so it
    does NOT add a false positive.

Trust-boundary discipline (T-09-W0-01 / T-09-W0-02): EVERY secret here is
SYNTHETIC — deterministically constructed JWTs carrying only a ``role`` claim
and a DUMMY signature (never a real key), and ``sb_secret_<random>`` uses a
fixed placeholder, not a live secret. The factory writes ONLY under the
caller-supplied ``root`` (no absolute paths). See ``PROVENANCE.md``.

stdlib-only (``json`` / ``base64`` / ``pathlib``) — no third-party deps so the
factory can be imported by ``conftest`` without import-time cost. The factory
does NOT git-init; the ``conftest`` ``expo_android_repo`` fixture (Plan 09-00
Task 2) owns that decision if a test needs git history.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

__all__ = ["make_expo_android_repo", "make_synthetic_jwt"]


def _b64url(raw: bytes) -> str:
    """base64url-encode WITHOUT padding (JWT segment convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_synthetic_jwt(role: str) -> str:
    """Build a SYNTHETIC, deterministic Supabase-shaped JWT carrying ``role``.

    header = ``{"alg":"HS256","typ":"JWT"}``,
    payload = ``{"role":<role>,"iss":"supabase"}``,
    signature = a DUMMY constant (NOT a real HMAC) so the token is obviously
    fake and can never authenticate against anything.

    The Tier-2 JWT-role helper (Plan 02) decodes the *unverified* payload and
    reads ``role`` — so a deterministic, signature-invalid token is exactly the
    right corpus: ``service_role`` -> flag, ``anon`` -> allowlist.
    """
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url(
        json.dumps({"role": role, "iss": "supabase"}).encode("utf-8")
    )
    # Obviously-fake fixed signature segment — never a real HMAC.
    signature = _b64url(b"synthetic-fixture-signature-not-a-real-key")
    return f"{header}.{payload}.{signature}"


# Deterministic synthetic tokens (module-level so tests can import & assert).
SERVICE_ROLE_JWT = make_synthetic_jwt("service_role")
ANON_JWT = make_synthetic_jwt("anon")

# A synthetic secret-prefixed key (Supabase June-2025 key system). The bytes
# after the prefix are a FIXED placeholder, not a live secret.
SB_SECRET_KEY = "sb_secret_0000fixture0000synthetic0000notreal"


def make_expo_android_repo(root: Path) -> Path:
    """Write a minimal Expo->Android tree under ``root`` and return it.

    Args:
        root: the directory to write into (a pytest ``tmp_path``). Created if
            absent. ALL writes stay under this path (no absolute paths).

    Returns:
        ``root`` (the repo root), for fluent use in tests.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    # --- package.json: expo + react-native deps so the detector says `expo`.
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "expo-fixture",
                "version": "0.0.0",
                "main": "node_modules/expo/AppEntry.js",
                "dependencies": {
                    "expo": "~51.0.0",
                    "react": "18.2.0",
                    "react-native": "0.74.0",
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # --- app.json: the Expo app manifest.
    (root / "app.json").write_text(
        json.dumps(
            {
                "expo": {
                    "name": "expo-fixture",
                    "slug": "expo-fixture",
                    "platforms": ["android"],
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # --- app.config.js: hardcoded service_role JWT in the `extra` block.
    # This is the catastrophic-case secret the Tier-2 pass MUST flag.
    (root / "app.config.js").write_text(
        "// SYNTHETIC fixture — the JWT below is a fake service_role token\n"
        "// (role claim only, dummy signature). NEVER a real key.\n"
        f'const SERVICE = "{SERVICE_ROLE_JWT}";\n'
        "\n"
        "module.exports = {\n"
        "  expo: {\n"
        "    name: 'expo-fixture',\n"
        "    extra: {\n"
        "      supabaseServiceRole: SERVICE,\n"
        "    },\n"
        "  },\n"
        "};\n",
        encoding="utf-8",
    )

    # --- .env: the PUBLIC anon key — must NEVER be flagged.
    (root / ".env").write_text(
        f"EXPO_PUBLIC_SUPABASE_ANON_KEY={ANON_JWT}\n"
        "EXPO_PUBLIC_SUPABASE_URL=https://fixture.supabase.co\n",
        encoding="utf-8",
    )

    # --- eas.json: build profile env block — benign var + sb_secret_ value.
    (root / "eas.json").write_text(
        json.dumps(
            {
                "cli": {"version": ">= 5.0.0"},
                "build": {
                    "production": {
                        "env": {
                            "EXPO_PUBLIC_API_URL": "https://api.fixture.example",
                            "SUPABASE_SERVICE_ROLE_KEY": SB_SECRET_KEY,
                        }
                    }
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # --- android native strings.xml: a native-injected api_key (mobsfscan).
    strings_dir = root / "android" / "app" / "src" / "main" / "res" / "values"
    strings_dir.mkdir(parents=True, exist_ok=True)
    (strings_dir / "strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        '    <string name="app_name">expo-fixture</string>\n'
        '    <string name="api_key">AIzaSyFIXTUREdummyAndroidNativeKey000000</string>\n'
        "</resources>\n",
        encoding="utf-8",
    )

    # --- client TS source under app/ (secret-free — no false positive).
    login_dir = root / "app" / "screens"
    login_dir.mkdir(parents=True, exist_ok=True)
    (login_dir / "Login.tsx").write_text(
        "import React from 'react';\n"
        "import { View, Text } from 'react-native';\n"
        "\n"
        "// Secret-free client screen — must NOT produce a footgun finding.\n"
        "export function Login() {\n"
        "  return (\n"
        "    <View>\n"
        "      <Text>Sign in</Text>\n"
        "    </View>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )

    return root
