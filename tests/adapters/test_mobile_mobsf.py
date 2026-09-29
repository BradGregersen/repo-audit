"""MOB-03 Tier-3a (9-T3a/9-T3b) — MobSF Docker static mapper (Plan 09-03, Wave 2).

Laid down in Wave 0 (Plan 09-00) as a RED-then-GREEN target. ``importorskip``
keeps the module SKIPPED until ``repo_audit.adapters.mobile.mobsf`` lands,
then these REAL assertions activate (03-01b SKIPPED->ACTIVE discipline).

Contract under test:
  * ``report_json`` (the hand-authored A4 fixture) maps to >=1 Finding with every
    raw secret from the fixture's ``secrets`` list REDACTED (T-9-04 / SC-5),
  * absent docker -> ``status == "unavailable"`` with no raise/hang (T-9-03).
"""
from __future__ import annotations

import pytest

mobsf = pytest.importorskip(
    "repo_audit.adapters.mobile.mobsf",
    reason="optional module repo_audit.adapters.mobile.mobsf not importable — feature not present in this build, or the install is incomplete",
)


def _map_report(report: dict):
    """Invoke the Wave-2 report_json mapper, tolerating naming variants."""
    for name in ("report_json_to_findings", "map_report_json", "map_mobsf_json"):
        fn = getattr(mobsf, name, None)
        if fn is not None:
            return fn(report)
    pytest.fail("mobsf exposes no report_json mapper")


def test_report_json_to_findings_redacted(mobsf_report_json):
    """report_json -> Findings; no raw secret from the fixture survives."""
    findings = _map_report(mobsf_report_json)
    assert len(findings) >= 1

    raw_secrets = list(mobsf_report_json.get("secrets") or []) + list(
        mobsf_report_json.get("possible_secrets") or []
    )
    assert raw_secrets, "fixture must seed at least one raw secret to redact"

    saw_redaction = False
    for f in findings:
        serialized = f.model_dump_json()
        for secret in raw_secrets:
            # The high-entropy VALUE portion (after any 'name : ' prefix) must
            # never appear verbatim in a serialized Finding.
            value = secret.split(" : ")[-1].split("=")[-1].strip()
            if value:
                assert value not in serialized
        if "[REDACTED:" in serialized:
            saw_redaction = True
    assert saw_redaction


def test_unavailable(fp):
    """Docker absent -> adapter returns status=='unavailable', no raise/hang."""
    if not hasattr(mobsf, "run_mobsf"):
        pytest.skip("Wave 2 run_mobsf entry point not yet landed")

    # Simulate docker being absent: any docker invocation fails to start.
    fp.register([fp.any()], callback=lambda process: (_ for _ in ()).throw(
        FileNotFoundError("docker")
    ))

    result = mobsf.run_mobsf(apk_path=None)
    assert result.status == "unavailable"


def test_static_scan_threads_timeout_to_slow_calls(tmp_path, monkeypatch):
    """upload, scan and report_json get the caller's timeout; delete_scan keeps the short one."""
    if not hasattr(mobsf, "_run_static_scan"):
        pytest.skip("_run_static_scan entry point not present")

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    seen: dict[str, float] = {}

    def fake_post(url, *, api_key, fields=None, file_field=None, timeout=mobsf._HTTP_TIMEOUT_SECONDS):
        seen[url.rsplit("/", 1)[-1]] = timeout
        return {"hash": "abc123"} if url.endswith("/upload") else {"ok": True}

    monkeypatch.setattr(mobsf, "_http_post", fake_post)
    mobsf._run_static_scan("http://127.0.0.1:8000", api_key="k", apk=apk, timeout_seconds=321.0)

    assert seen["upload"] == 321.0
    assert seen["scan"] == 321.0
    assert seen["report_json"] == 321.0
    assert seen["delete_scan"] == mobsf._HTTP_TIMEOUT_SECONDS


def test_http_post_passes_timeout_to_urlopen(monkeypatch):
    """The socket timeout handed to urlopen is the one the caller asked for."""
    captured: dict[str, float] = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout):
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(mobsf.urllib.request, "urlopen", fake_urlopen)
    mobsf._http_post("http://127.0.0.1:8000/api/v1/scan", api_key="k", fields={}, timeout=45.0)
    assert captured["timeout"] == 45.0
    mobsf._http_post("http://127.0.0.1:8000/api/v1/delete_scan", api_key="k", fields={})
    assert captured["timeout"] == mobsf._HTTP_TIMEOUT_SECONDS
