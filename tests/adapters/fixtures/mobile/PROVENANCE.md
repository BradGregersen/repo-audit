# Phase 9 mobile fixtures — provenance

This directory holds the synthetic Expo->Android repo factory and the recorded
JSON fixtures the Phase 9 (Mobile Pentest & Bundled Secrets) Wave 1/2 tests run
against. Provenance is documented here per the Phase-6/7/8 recorded-fixture
precedent (`tests/adapters/sarif/fixtures/PROVENANCE.md`,
dependency-cruiser docs-sourced labelling).

## `expo_repo_factory.py` — SYNTHETIC (no real secret)

`make_expo_android_repo(root)` writes a minimal Expo/React-Native -> Android
tree under a caller-supplied `tmp_path`. It is **entirely synthetic**:

- The `service_role` JWT (`app.config.js`) and the `anon` JWT (`.env`) are built
  deterministically by `make_synthetic_jwt(role)` — header `{"alg":"HS256",
  "typ":"JWT"}`, payload `{"role":<role>,"iss":"supabase"}`, and a **dummy
  constant signature** (NOT a real HMAC). They carry only a `role` claim and
  cannot authenticate against anything.
- `sb_secret_0000fixture0000synthetic0000notreal` (eas.json) is a fixed
  placeholder, not a live secret.
- The native `strings.xml` `api_key` (`AIzaSy…FIXTURE…`) is an obviously-fake
  Android-key-shaped placeholder.

Trust boundary (threat-register **T-09-W0-01 / T-09-W0-02**): all fixture
secrets are synthetic and the factory writes ONLY under the supplied `root`
(no absolute paths). The fixture itself is therefore not a leak vector.

## mobsfscan SARIF — REUSED (live mobsfscan 0.4.5)

The Wave 1 MOB-01 test (`test_mobile_mobsfscan.py`) reuses the EXISTING,
live-recorded mobsfscan SARIF fixture rather than re-recording:

    tests/adapters/sarif/fixtures/mobsfscan/sample.sarif

It was captured live against mobsfscan **0.4.5** during Phase-6 fixture
recording (see `tests/adapters/sarif/fixtures/PROVENANCE.md`). It round-trips
through the single `sarif_to_findings` parser with `source_tool="mobsfscan"`,
`default_dimension="security"`.

## `mobsf_report_json.json` — HAND-AUTHORED (A4, re-record live when image pulled)

This is a **hand-authored** document shaped against the MobSF
`StaticAnalyzerAndroid` `report_json` model. Recording a live fixture requires
the `opensecurity/mobile-security-framework-mobsf` Docker image, which is **not
pulled** in this environment — so, mirroring the Phase-6 dependency-cruiser
PROVENANCE precedent (label-and-defer), this fixture is authored against the
documented shape and must be **re-recorded live when the image is pulled**.

Assumptions-log reference: **A4** (09-RESEARCH.md) — "the MobSF `report_json`
shape exposes secrets under `secrets` / `hardcoded_secrets` / `possible_secrets`
keys; exact key names vary by MobSF version." The Plan-03 Tier-3a mapper consumes:

- top-level `"secrets"` — list of raw secret strings (this fixture seeds a
  synthetic `service_role`-shaped JWT VALUE so the Plan-03 redaction test has
  something to redact),
- top-level `"possible_secrets"` — list,
- `"findings"` — a `{rule_title: {severity, files, metadata}}` mapping with
  `severity ∈ {high, warning, info}`.

All secret VALUES inside `"secrets"` / `"possible_secrets"` are the same
synthetic tokens the Expo factory emits — never a real key.
