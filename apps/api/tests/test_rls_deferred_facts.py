"""Label joins that feed a decision read facts, not policied rows (S1).

Static: no database. 2026-09-25. Under row-level security a LEFT JOIN to
a row the reader may not see reads as no row at all, and a label computed
as the strictest of what the join found then reads LOW: the anti-join
trap, turned into a leak. Every such join over a table the registry puts
under policy reads the definer fact functions instead (`iam.element_facts`,
`iam.case_facts`), and each one converted is pinned here by the SQL
constant or function that carries it, so a later edit cannot quietly put
the plain join back.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def _constant(rel: str, name: str) -> str:
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{rel} has no constant {name}: the table below is stale")


#: (module, constant) -> (the fact read it must make, the plain join it
#: must not).
_CONSTANTS = {
    ("proposals.py", "_SOURCE_FROM"): (
        ("iam.element_facts('document', p.document_id)",
         "iam.element_facts('proposal_block', p.id)"),
        r"JOIN\s+(collect\.document|comms\.contact_block)\b"),
}


def test_every_converted_label_join_reads_a_fact_function():
    problems = []
    for (rel, name), (facts, forbidden) in _CONSTANTS.items():
        text = _constant(rel, name)
        for fact in facts:
            if fact not in text:
                problems.append(f"{rel}:{name} no longer reads {fact}")
        if re.search(forbidden, text):
            problems.append(f"{rel}:{name} joins the policied table again")
    assert not problems, problems


def test_the_lookup_ledger_reads_entity_and_sample_labels_as_facts():
    """lookups.py composes a lookup's read label from its entity's and its
    sample's. As plain LEFT JOINs, a RED entity the caller cannot see read
    as no entity and the lookup (its query value included) as the case's
    label; a selector subject on such an entity was sent at that label."""
    text = (SRC / "lookups.py").read_text(encoding="utf-8")
    assert not re.search(r"LEFT JOIN\s+(core\.node|lab\.sample)\b", text)
    assert "iam.element_facts('node', l.node_id)" in text
    assert "iam.element_facts('node', s.node_id)" in text
    assert "iam.element_facts('sample', l.sample_id)" in text


def test_the_cross_case_document_search_runs_in_the_definer_function():
    """curation.SearchService._document_rows: full text and trigram are not
    leakproof, so as the request role the search could use neither index
    (0117)."""
    tree = ast.parse((SRC / "curation.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_document_rows")
    code = ast.unparse(fn)
    assert "iam.search_document_hits(" in code
    assert "collect.document" not in code
