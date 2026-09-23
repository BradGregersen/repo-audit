# Supabase Fixture Provenance (Phase 08, Plan 01, Task 3)

Three frozen fixtures every Wave 1 supabase collector (Plans 02-04) unit-tests
against OFFLINE — no docker, no node, no live database. Mirrors the Phase 7
recorded-fixture discipline (`tests/adapters/sca/fixtures/PROVENANCE.md`).

**Capture date:** 2026-06-02. **Host:** linux-x86_64.

## Tool versions

| Tool | Version | Notes |
|------|---------|-------|
| squawk-cli | 2.55.0 | pip dep declared Plan 01 Task 1 |
| pgrls | 0.14.0 | pip dep declared Plan 01 Task 1 (Beta) |
| splinter.sql | supabase/splinter @ a7f71080ed059de8a7f00addd71ade19b82a4108 | vendored Plan 01 Task 1 |

## Fixtures

### `squawk.json` — LIVE-CAPTURED (real tool output)

Captured by running the **real vendored** `squawk-cli 2.55.0` with
`--reporter=json` over a hand-authored destructive migration (a `DROP COLUMN`,
a non-`CONCURRENTLY` `CREATE INDEX`, and a `NOT NULL` add) — the lint surface
RLS-02 (migration-safety) targets. Exact recording argv:

```
squawk --reporter=json <migration.sql>
```

(exit code **1** = lints found, squawk's normal "issues detected" signal, NOT a
failure.) The migration was author-controlled (no secrets, threat T-08 accept).
The absolute `file` path in each row was normalized to a stable relative
`supabase/migrations/0009_destructive.sql` for host-independence; all other
fields (`rule_name`, `level`, `message`, `line`/`column`, `help`) are verbatim
real output. Rules present: `ban-drop-column`,
`require-concurrent-index-creation`, `prefer-robust-stmts`,
`require-timeout-settings`, `prefer-bigint-over-int`.

the example app's own SQL (`packages/api-client/sql/*.sql`) is purely additive (no
destructive ops), so a destructive migration was authored specifically to
exercise squawk's RLS-02 lints — the same rationale a real `repo-audit scan` applies
when it lints a repo's actual migrations.

### `splinter_rows.json` — DOC-AUTHORED (faithful to the vendored SQL shape)

splinter returns lint rows ONLY when its `splinter.sql` is executed against a
LIVE supabase/postgres database (the ephemeral-PG lifecycle is Plan 02's
deliverable — not available at Plan 01 time). These rows are therefore
hand-authored to match the **exact 10-column shape and field values** emitted
by the vendored `splinter.sql` @ a7f71080 — the `name`/`title`/`level`/`facing`/
`categories`/`remediation` values for each rule were read directly out of the
vendored SQL's `select ... as <col>` blocks (mirrors the Phase 6
dependency-cruiser docs-sourced precedent). The four rows cover every
level->Severity + categories->Dimension branch Plan 02's row-mapper needs:

| name | level | categories |
|------|-------|------------|
| `rls_disabled_in_public` | ERROR | SECURITY |
| `rls_references_user_metadata` | ERROR | SECURITY |
| `security_definer_view` | ERROR | SECURITY |
| `auth_rls_initplan` | WARN | PERFORMANCE |

**Re-record action (Plan 02):** once the ephemeral-PG lifecycle lands, re-capture
these rows live by applying the example app's real SQL to the supabase/postgres image and
executing the vendored `splinter.sql`; replace this doc-authored set and update
this note.

### `pgrls.sarif.json` — DOC-AUTHORED (faithful SARIF 2.1.0)

pgrls (like splinter) introspects a LIVE database — no `.sql`-file mode. This
SARIF 2.1.0 document is hand-authored to the shape pgrls's `--format sarif`
emits (tool driver `pgrls`, `runs[].results[]` with `ruleId` + `level` +
`message.text` + `locations[].physicalLocation` artifact/region +
`rules[].properties.security-severity`). **Verified at capture time to
round-trip through the shared `sarif_to_findings()` with NO per-tool shim
(A2)** — see the Plan 01 SUMMARY self-check. Two results: an `error`-level
over-permissive policy and a `warning`-level missing-policy, both phrased with
verify-language (CRIT-4) so they survive the verify-phrasing tripwire.

**Re-record action (Plan 03):** capture real pgrls SARIF against the ephemeral
DB once the lifecycle lands; replace this doc-authored document.
