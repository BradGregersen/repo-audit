"""COLL-02 tests. STUB — implementation lands in Plan 02-03."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-03 implements loc_inventory")


def test_loc_inventory_emits_per_language_findings(fake_repo):
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n", "b.ts": "const b = 2;\n"}, name="loc-mix")
    result = run(repo, {})
    assert result.status == "ok"
    langs = {f.evidence.parsed_value.get("language") for f in result.findings}
    assert "Python" in langs or "TypeScript" in langs


def test_loc_inventory_strips_scc_Content_field(fake_repo):
    """Pitfall 1: base64 Content field must be stripped before findings construct."""
    from repo_audit.collectors.loc_inventory import run
    repo = fake_repo({"a.py": "x=1\n" * 100}, name="content-strip")
    result = run(repo, {})
    for f in result.findings:
        for k, v in f.evidence.parsed_value.items():
            if isinstance(v, str):
                assert "Content" not in k


def test_loc_inventory_missing_scc_binary_returns_unavailable(monkeypatch, fake_repo):
    from repo_audit.collectors import loc_inventory as li
    repo = fake_repo({"a.py": "x=1\n"}, name="no-scc")
    monkeypatch.setattr(li, "_scc_binary_path", lambda: __import__("pathlib").Path("/nonexistent/scc"))
    result = li.run(repo, {})
    assert result.status == "unavailable"
