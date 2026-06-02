# Phase 10 (SAST — Semgrep) Wave-0 Fixture Provenance

> Status disclosure for the `tests/adapters/fixtures/sast/` corpus.

## SARIF fixtures — HAND-AUTHORED

Both `owasp_top_ten.sarif` and `secrets_anon.sarif` are **hand-authored** against
the live-verified Semgrep 1.163.0 SARIF shape (see 10-RESEARCH.md § Code Examples,
A2). They are NOT recorded from a live Semgrep run. They faithfully reproduce the
exact field shapes Semgrep emits:

- `runs[0].tool.driver.name = "Semgrep OSS"`, `driver.semanticVersion = "1.163.0"`.
- `runs[0].results[].level` is explicit JSON `null` on the OWASP fixture — Semgrep
  sets `result.level = null` and the faithful severity lives in
  `runs[0].tool.driver.rules[].defaultConfiguration.level`
  (∈ {`error`, `warning`, `note`}). This is the Pitfall-1 severity-collapse shape.
- OWASP rules carry `properties.tags` with `CWE-...` + `OWASP-A...:2021` entries
  and **no** `security-severity` numeric (0/544 verified live on owasp-top-ten) —
  so the parser's security-severity numeric band cannot short-circuit the
  level-based path the Wave-1 fix targets.

**A2 follow-up:** re-record these fixtures from a real per-pack `semgrep --sarif`
run in a Wave-1/2 follow-up to pin any further per-pack deviations.

### `owasp_top_ten.sarif`

Two results, two rules:
- `python...dangerous-os-command` — `defaultConfiguration.level = "error"`,
  OWASP-A03 (Injection) + CWE-78 tags, `result.level = null`. With the CURRENT
  parser this floors to `info`; with the Wave-1 fallback it yields faithful
  `critical` (capped to `major` at confidence=candidate per SCH-04).
- `typescript.react...react-dangerouslysetinnerhtml` —
  `defaultConfiguration.level = "warning"`, OWASP-A03 + CWE-79 tags,
  `result.level = null`. Wave-1 yields faithful `major`.

### `secrets_anon.sarif`

A `p/secrets`-style rule (`generic.secrets...detected-jwt-token`) with two results:
- **Result A (.env)** — the PUBLIC `EXPO_PUBLIC_SUPABASE_ANON_KEY` (matches
  `footguns._ANON_ALLOWLIST`). This is the false positive the SAST-03 drop must
  REMOVE.
- **Result B (src/config.ts)** — a genuine `SUPABASE_SERVICE_ROLE_KEY`-shaped
  secret that does NOT match `_ANON_ALLOWLIST`. This is the real finding SAST-03
  must KEEP and REDACT (with an RLS cross-link).

## Secret values — SYNTHETIC

Every secret/key string in the SARIF fixtures and in `vuln_repo_factory.py` is
**synthetic and obviously fake**: dummy JWTs carrying only an unsigned header and
a `role` claim, with literal `FAKE_SYNTHETIC_..._SIGNATURE_DO_NOT_USE` signatures.
They are not real Supabase keys, decode to nothing useful, and are not a leak
vector (T-10-W0-01).

## `vuln_repo_factory.py` — SYNTHETIC

`make_sast_vuln_repo(root)` builds a synthetic repo (stdlib only, no git-init,
writes only under the caller-supplied `root` — T-10-W0-02). It contains an
intentionally-vulnerable `src/vuln.py` (OS-command-injection, OWASP-A03), a benign
`src/component.tsx`, a `package.json` declaring react/react-native/expo (so the
detector selects `p/react`), and a `.env` with the synthetic public anon key.
