"""Every similarity statement carries its labels, read from the source
(F6.3, 2026-09-24).

A SQL literal in embeddings.py or http/routers/similarity.py that reads a
document's content (title, body, author, URL, source name) must check the
document's compartments (`d.compartments <@`) and its source's label
(`s.classification <=`), except the embedding pass's own SYSTEM reads,
named below with the reason. A literal that orders vector rows by
distance must stay inside one partition (`read_compartments = '{}'`) or
inside the reader's compartments (`read_compartments <@`).

This does not lean on test_document_reads_check_compartments.py: a
substring such as `read_compartments <@` would satisfy a looser scan while
the document's own compartments went unchecked.

Pure: parses the source.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
FILES = [SRC / "embeddings.py", SRC / "http" / "routers" / "similarity.py"]

#: The pass's SYSTEM reads: they read documents to embed them, or to judge
#: a claim by what it cites, and return nothing to a person.
SYSTEM_READS = {
    "read_items": "the pass's reader: every document, to embed it",
    "_assertion_facts_sql": "a claim's cited document, for the claim's gate",
}

DOCUMENT = re.compile(r"\bcollect\.document\b(?!_)")
CONTENT = re.compile(r"\b(title|body_text|author_handle|external_url|s\.name)\b")
DISTANCE = re.compile(r"collect\.document_embedding[\s\S]*ORDER BY[\s\S]*<=>|"
                      r"<=>[\s\S]*collect\.document_embedding")


def _literals(path: Path):
    """(enclosing function, text) for every string constant."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []

    def walk(node, where):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef,
                                                     ast.AsyncFunctionDef)) else where
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                out.append((where, child.value))
            walk(child, inner)
    walk(tree, "<module>")
    return out


def test_every_document_content_read_checks_compartments_and_the_source():
    checked = 0
    for path in FILES:
        for where, text in _literals(path):
            if not DOCUMENT.search(text) or not CONTENT.search(text):
                continue
            if where in SYSTEM_READS:
                continue
            checked += 1
            assert "d.compartments <@" in text, (path.name, where, text[:120])
            assert "s.classification <=" in text, (path.name, where, text[:120])
            assert "d.classification <=" in text, (path.name, where, text[:120])
    assert checked >= 2, "the scan found no document read: it broke"


def test_every_distance_order_stays_inside_a_partition_or_the_readers_keys():
    checked = 0
    for path in FILES:
        for where, text in _literals(path):
            if "collect.document_embedding" not in text or "<=>" not in text:
                continue
            checked += 1
            assert ("read_compartments = '{" in text
                    or "read_compartments <@" in text), (where, text[:160])
    assert checked >= 2


def test_the_system_reads_are_still_where_they_are_named():
    names = {where for path in FILES for where, _ in _literals(path)}
    assert set(SYSTEM_READS) <= names
