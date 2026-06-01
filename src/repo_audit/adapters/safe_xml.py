"""Safe XML parsing seam for tool-provided XML.

This module is the ONLY sanctioned entry point for parsing third-party XML in
Repo Audit. Any tool output that arrives as XML — JUnit reports, kover
coverage, and any hadolint/checkov XML if those tools ever emit it (Phase 11/13)
— MUST be parsed through ``parse_xml`` here, never through the standard library
parser.

Why: tool output is untrusted and may be hostile. A nested-entity "billion
laughs" bomb or an external-entity (XXE) document can exhaust memory or exfiltrate
local files if parsed with a naive parser. The standard-library parser does not
defend against these by default, so it is banned for third-party XML (CLAUDE.md
convention; threat T-06-05 / T-06-06).

This helper is backed by ``defusedxml``, whose parser refuses entity expansion,
DTD processing, and external references by default. When such constructs are
present the parser raises a ``defusedxml`` refusal exception
(``EntitiesForbidden`` / ``DTDForbidden`` / ``ExternalReferenceForbidden``,
subclasses of ``DefusedXmlException``). We deliberately let those refusals
propagate: the caller — a future XML-emitting tool parser — maps the refusal to
``status='unavailable'`` rather than ingesting a malicious document.
"""

from __future__ import annotations

import os
from pathlib import Path

# defusedxml is the only sanctioned XML parser for third-party input. The
# standard-library tree parser is intentionally NOT imported here.
import defusedxml.ElementTree as DefusedET
from defusedxml.ElementTree import ParseError

# Re-export the refusal exceptions so callers can map them to
# status='unavailable' without reaching into defusedxml internals.
from defusedxml.common import (
    DefusedXmlException,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

__all__ = [
    "parse_xml",
    "DefusedXmlException",
    "DTDForbidden",
    "EntitiesForbidden",
    "ExternalReferenceForbidden",
    "ParseError",
]


def _looks_like_path(value: str) -> bool:
    """Heuristic: a short, single-line string that names an existing file is a path.

    XML documents contain angle brackets and/or newlines; filesystem paths
    typically do not. We only treat the input as a path when it both lacks XML
    markup and points at an existing file, so an inline XML string is never
    accidentally resolved against the filesystem.
    """
    if "<" in value or "\n" in value:
        return False
    try:
        return os.path.isfile(value)
    except (OSError, ValueError):
        return False


def parse_xml(text_or_path: str | os.PathLike[str]):
    """Parse tool-provided XML through defusedxml and return the root element.

    Accepts either:
      * a ``str`` / ``os.PathLike`` that names an existing file (the file is read
        and parsed), or
      * a ``str`` containing the XML document itself.

    Returns the root ``Element`` of the parsed tree.

    Raises (and intentionally does NOT swallow) the ``defusedxml`` refusal
    exceptions when the document attempts entity expansion, DTD processing, or
    external references:

      * ``EntitiesForbidden`` — internal entity definitions (billion-laughs).
      * ``DTDForbidden`` — a DOCTYPE / DTD is present.
      * ``ExternalReferenceForbidden`` — an external entity / system reference.

    Malformed-but-benign XML raises ``ParseError``. Callers map any of these to
    ``status='unavailable'`` per the adapter failure contract; this helper never
    expands a hostile document.
    """
    if isinstance(text_or_path, os.PathLike):
        path = Path(os.fspath(text_or_path))
        return DefusedET.fromstring(path.read_text(encoding="utf-8"))

    if isinstance(text_or_path, str) and _looks_like_path(text_or_path):
        return DefusedET.fromstring(Path(text_or_path).read_text(encoding="utf-8"))

    return DefusedET.fromstring(text_or_path)
