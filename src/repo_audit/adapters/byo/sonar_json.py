"""Re-export shim: ``byo.sonar_json`` -> ``byo.normalizers.sonar_json``.

The SonarQube JSON->Finding normalizer's canonical home is
``byo/normalizers/sonar_json.py`` (alongside the Socket.dev normalizer). This
thin module re-exports it at ``byo.sonar_json`` so callers (and the Plan-16-01
test contract ``tests/adapters/byo/test_sonar_normalizer.py``) can import it by
the shorter path. There is NO logic here — see the normalizers package.
"""
from repo_audit.adapters.byo.normalizers.sonar_json import (
    sonar_json_to_findings,
)

__all__ = ["sonar_json_to_findings"]
