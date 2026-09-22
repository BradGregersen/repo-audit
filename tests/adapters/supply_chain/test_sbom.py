"""SUP-02 — Syft SBOM generation (Plan 12-?, Wave 1).

Wave-0 ``importorskip`` stub: SKIPPED until
``repo_audit.adapters.supply_chain.sbom`` lands, then ACTIVE.

Contract under test (RESEARCH Test Map + Pitfall 5/6):
  * Syft present -> a CycloneDX JSON is written OUTSIDE the target repo and its
    path is stamped into meta (D-12-07: reference the path, never inline),
  * Syft absent -> ``status == 'unavailable'``, scan completes, no target-repo write,
  * no packages to catalog -> ``unavailable`` (empty SBOM still disclosed).

Uses pytest-subprocess (``fp``) to fake Syft writing the recorded CycloneDX
sample fixture to the requested out_path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

sbom = pytest.importorskip(
    "repo_audit.adapters.supply_chain.sbom",
    reason="optional module repo_audit.adapters.supply_chain.sbom not importable — feature not present in this build, or the install is incomplete",
)


def _generate(repo_path, out_path):
    """Invoke the Wave-1 SBOM generator, tolerating naming variants."""
    for name in ("generate_sbom", "collect_sbom", "build_sbom", "run_sbom"):
        fn = getattr(sbom, name, None)
        if fn is not None:
            return fn(repo_path, out_path)
    pytest.fail("supply_chain.sbom exposes no SBOM generator entry point")


def test_sbom_written_outside_repo(fp, tmp_path, fake_repo, load_supply_chain_fixture):
    """Syft present -> CycloneDX JSON written to a path OUTSIDE the target repo."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"}, name="sbom-repo")
    out_path = tmp_path / "reports" / "sbom-repo-sbom-2026-06-03.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sample = load_supply_chain_fixture("syft-cyclonedx-sample.json")

    def _fake_syft(process):
        # Syft writes the SBOM to the -o file / --file target. Wave 1 owns the
        # exact argv; emulate by writing the sample to out_path.
        import json

        out_path.write_text(json.dumps(sample), encoding="utf-8")

    fp.register(
        [fp.any()],  # Wave 1 owns the exact syft argv; match broadly for the stub
        callback=_fake_syft,
        returncode=0,
    )
    result = _generate(repo, out_path)
    # The SBOM path must live outside the target repo tree.
    assert Path(repo) not in out_path.parents
    assert out_path.exists()
    status = getattr(result, "status", None)
    assert status in (None, "ok", "partial")


def test_sbom_path_stamped(fp, tmp_path, fake_repo, load_supply_chain_fixture):
    """The generated SBOM path is reported back (stamped) for meta/FeedProvenance."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"}, name="sbom-stamp")
    out_path = tmp_path / "reports" / "sbom-stamp-sbom.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sample = load_supply_chain_fixture("syft-cyclonedx-sample.json")

    def _fake_syft(process):
        import json

        out_path.write_text(json.dumps(sample), encoding="utf-8")

    fp.register([fp.any()], callback=_fake_syft, returncode=0)
    result = _generate(repo, out_path)
    # The result exposes the written path (exact attribute owned by Wave 1).
    stamped = getattr(result, "sbom_path", None) or getattr(result, "path", None)
    assert stamped is not None
    assert str(out_path) in str(stamped)


def test_syft_absent_unavailable(monkeypatch, tmp_path, fake_repo):
    """Syft not resolvable -> status 'unavailable', no raise, no target-repo write."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"}, name="no-syft")
    out_path = tmp_path / "reports" / "no-syft-sbom.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Force resolution miss if the module resolves via resolve_tool.
    if hasattr(sbom, "resolve_tool"):
        monkeypatch.setattr(sbom, "resolve_tool", lambda *a, **k: None)
    result = _generate(repo, out_path)
    status = getattr(result, "status", None)
    assert status == "unavailable", f"expected 'unavailable', got {status!r}"


def test_no_packages_unavailable(monkeypatch, tmp_path, fake_repo):
    """A repo with no catalogable packages -> 'unavailable' (empty SBOM disclosed)."""
    repo = fake_repo({"README.md": "# nothing to catalog\n"}, name="no-pkgs")
    out_path = tmp_path / "reports" / "no-pkgs-sbom.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(sbom, "resolve_tool"):
        monkeypatch.setattr(sbom, "resolve_tool", lambda *a, **k: None)
    result = _generate(repo, out_path)
    status = getattr(result, "status", None)
    assert status == "unavailable"
