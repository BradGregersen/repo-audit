"""Re-export shim: ``byo.socket_json`` -> ``byo.normalizers.socket_json``.

The Socket.dev JSON->Finding normalizer's canonical home is
``byo/normalizers/socket_json.py`` (alongside the SonarQube normalizer). This
thin module re-exports it at ``byo.socket_json`` so callers (and the Plan-16-01
test contract ``tests/adapters/byo/test_socket_normalizer.py``) can import it by
the shorter path. There is NO logic here — see the normalizers package.
"""
from repo_audit.adapters.byo.normalizers.socket_json import (
    socket_json_to_findings,
)

__all__ = ["socket_json_to_findings"]
