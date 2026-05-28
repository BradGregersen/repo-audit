"""Repo Audit — polyglot repo-health audit CLI."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("repo-audit")
except PackageNotFoundError:  # editable install pre-build edge case
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
