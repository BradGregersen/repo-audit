"""Unit tests for the RLS-04 service_role-in-client footgun grep (Plan 08-04).

The deliberately-tiny static grep (D-08-11) that complements splinter's native
footgun lints: it flags a ``service_role``-style key reference reachable from
CLIENT code, client-paths-only (edge/server/tests excluded), with the public
anon key allowlisted (SAST-03/MOB-02 project-wide rule). Every finding is
heuristic/candidate, verify-phrased, cross-links MOB-02/SAST, and carries a
REDACTED span — never the raw key value.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.supabase.footguns import (
    scan_service_role_in_client,
)
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)


def _write(repo: Path, rel: str, body: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Positive: a service_role key reference in client-reachable code is flagged.


def test_service_role_env_name_in_client_is_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/lib.ts",
        "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.status == "ok"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.evidence_type == "heuristic"
    assert f.confidence == "candidate"
    assert f.dimension == "security"
    assert f.file is not None and "app/lib.ts" in f.file
    assert f.line is not None and f.line >= 1


def test_sb_secret_prefix_literal_is_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/client.ts",
        'const k = "sb_secret_AbCdEf123456";\n',
    )
    result = scan_service_role_in_client(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].dimension == "security"


def test_create_client_with_service_role_arg_is_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "components/admin.tsx",
        "const c = createClient(supabaseUrl, serviceRoleKey);\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Exclusions: edge functions, server-only dirs, and tests are NOT flagged.


def test_edge_function_hit_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "supabase/functions/admin/index.ts",
        "const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.findings == []


def test_server_dir_hit_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "server/db.ts",
        "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.findings == []


def test_test_file_hit_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/__tests__/auth.test.ts",
        "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
    )
    # also a *.test.* under a client dir (not in __tests__)
    _write(
        tmp_path,
        "app/lib.test.ts",
        "const key = process.env.SERVICE_ROLE;\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.findings == []


# ---------------------------------------------------------------------------
# Allowlist: the public anon/publishable key is NEVER flagged.


def test_anon_key_env_name_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/supabase.ts",
        "const k = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;\n"
        "const c = createClient(url, anonKey);\n",
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.findings == []


def test_sb_publishable_prefix_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/supabase.ts",
        'const k = "sb_publishable_AbCdEf123456";\n',
    )
    result = scan_service_role_in_client(tmp_path)
    assert result.findings == []


# ---------------------------------------------------------------------------
# Verify-phrasing + cross-link + redaction.


def test_finding_is_verify_phrased_and_cross_links(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/lib.ts",
        "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
    )
    result = scan_service_role_in_client(tmp_path)
    f = result.findings[0]
    # Cross-link to MOB-02 / SAST present in the report prose.
    prose = " ".join(
        [f.recommendation, f.confidence_caveat or "", f.evidence.output_snippet]
    )
    assert "MOB-02" in prose or "SAST" in prose
    # Must pass the shared CRIT-4 tripwire (verify-phrased, no enforcement words).
    assert_verify_phrasing(result.findings)


def test_matched_span_is_redacted_not_raw(tmp_path: Path) -> None:
    secret = "sb_secret_SuperSecretValue999"
    _write(tmp_path, "app/client.ts", f'const k = "{secret}";\n')
    result = scan_service_role_in_client(tmp_path)
    f = result.findings[0]
    blob = (
        f.recommendation
        + (f.confidence_caveat or "")
        + f.evidence.output_snippet
        + str(f.evidence.parsed_value)
    )
    assert secret not in blob
    assert "REDACTED" in f.evidence.output_snippet


# ---------------------------------------------------------------------------
# Clean repo: no hits → ok + empty (NOT unavailable).


def test_clean_repo_is_ok_not_unavailable(tmp_path: Path) -> None:
    _write(tmp_path, "app/safe.ts", "const c = createClient(url, anonKey);\n")
    result = scan_service_role_in_client(tmp_path)
    assert result.status == "ok"
    assert result.findings == []
