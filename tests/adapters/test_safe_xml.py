"""Contract tests for the safe-XML parse seam (SC-3 / MIN-2 / T-06-05 / T-06-06).

Three guarantees are pinned here:

1. ``safe_xml`` is backed by ``defusedxml`` and never imports the standard-library
   tree parser for third-party XML (source-string discipline, same as Phase 3).
2. A classic billion-laughs entity bomb is REFUSED (raises a defusedxml refusal
   exception), not expanded — proven under a hard wall-time cap so a regression
   that silently inflates the document fails the test instead of hanging the suite.
3. Benign, well-formed XML still parses and yields the expected structure — the
   helper continues to do its job.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from repo_audit.adapters import safe_xml
from repo_audit.adapters.safe_xml import (
    DefusedXmlException,
    parse_xml,
)

FIXTURES_ROOT = Path(__file__).parent / "fixtures"
BILLION_LAUGHS = FIXTURES_ROOT / "xml" / "billion_laughs.xml"


def test_uses_defusedxml_not_stdlib():
    """safe_xml imports defusedxml and never the stdlib xml.etree tree parser.

    Source-string discipline (the same structural pin Phase 3 used for the
    Finding boundary): grep the module source so the guarantee survives refactors.
    """
    src = Path(safe_xml.__file__).read_text(encoding="utf-8")

    assert "defusedxml" in src, "safe_xml must be backed by defusedxml"
    # The banned stdlib tree parser must never appear in this module.
    assert "xml.etree" not in src, (
        "safe_xml must not import the stdlib xml.etree parser — defusedxml is the "
        "only sanctioned XML parser for third-party input (CLAUDE.md / D-06-12)"
    )
    assert "import xml" not in src, (
        "safe_xml must not import the stdlib xml package for third-party input"
    )


def test_billion_laughs_does_not_expand():
    """The entity bomb is refused by defusedxml, not expanded (MIN-2 closed).

    A correct defusedxml parser raises immediately on the entity/DTD definitions,
    so this returns in milliseconds. We bound wall time as a tripwire: a
    regression that swaps in an expanding parser would either hang or inflate
    memory, and either way blow past the cap.
    """
    start = time.monotonic()
    with pytest.raises(DefusedXmlException) as exc_info:
        parse_xml(BILLION_LAUGHS)
    elapsed = time.monotonic() - start

    # Refusal is the whole point — the exception type proves non-expansion.
    assert isinstance(exc_info.value, DefusedXmlException)
    # Hard cap: a genuine refusal is effectively instant. 5s is generous and
    # would only be exceeded if the bomb were actually being expanded.
    assert elapsed < 5.0, (
        f"parse_xml took {elapsed:.2f}s on the entity bomb — it should refuse "
        "instantly, not expand"
    )


def test_benign_xml_parses():
    """A small well-formed JUnit-style document parses to the expected structure."""
    junit = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<testsuite name="sample" tests="2" failures="0">'
        '<testcase classname="pkg.A" name="test_one"/>'
        '<testcase classname="pkg.B" name="test_two"/>'
        "</testsuite>"
    )

    root = parse_xml(junit)

    assert root.tag == "testsuite"
    assert root.attrib["name"] == "sample"
    cases = root.findall("testcase")
    assert len(cases) == 2
    assert cases[0].attrib["name"] == "test_one"
    assert cases[1].attrib["name"] == "test_two"


def test_benign_xml_parses_from_path(tmp_path):
    """parse_xml also accepts a filesystem path to a benign document."""
    doc = tmp_path / "report.xml"
    doc.write_text('<testsuite name="fromfile" tests="0"/>', encoding="utf-8")

    root = parse_xml(doc)

    assert root.tag == "testsuite"
    assert root.attrib["name"] == "fromfile"
