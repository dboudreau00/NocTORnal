"""The merge set-aside column comment names both reasons (Alembic 0185, decision 176).

`core.node_merge_edge.deleted_by_merge` was written (0055) for a tie between the two entities merged, which
would become a self-loop. Since decision 176 it also marks a duplicate the merge set aside because the
person merging could not read it. One flag covers both; the comment says so, and says where the two are told
apart. The last test holds the comment, the merge record's combined count and the audit detail's split
to one another, so none of them drifts from what the comment says.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from uuid import UUID

import pytest

import graph_visibility_support as g
import rls_support as s
from rolled_back import rolled_back

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"

_DESCRIPTION = """SELECT col_description('core.node_merge_edge'::regclass, a.attnum)
                    FROM pg_attribute a
                   WHERE a.attrelid = 'core.node_merge_edge'::regclass
                     AND a.attname = 'deleted_by_merge'"""


def _migration(name: str):
    path = next(VERSIONS.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m_setaside_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _comment(conn) -> str:
    return conn.execute(_DESCRIPTION).fetchone()[0]


@s.GATED
def test_the_deleted_by_merge_comment_names_both_reasons():
    m = _migration("0185")
    conn = s.owner_conn()
    try:
        text = _comment(conn)
    finally:
        conn.close()
    assert text == m.COMMENT
    for phrase in ("self-loop", "Set aside", "decision 176", "NODE_MERGED",
                   "edges_self_loop_deleted", "edges_duplicate_folded", "must stay retired"):
        assert phrase in text, phrase
    assert "(s)" not in text and " -- " not in text
    assert "\u2013" not in text and "\u2014" not in text


@s.GATED
def test_the_revision_round_trips_the_comment_to_the_0055_text():
    m = _migration("0185")
    with rolled_back(s.owner_conn) as conn:
        m.run = lambda sql: conn.execute(sql)
        m.downgrade()
        assert _comment(conn) == m.PRIOR_COMMENT_0055
        assert "Set aside" not in _comment(conn)
        m.upgrade()
        assert _comment(conn) == m.COMMENT
        m.downgrade()
    conn = s.owner_conn()
    try:
        assert _comment(conn) == m.COMMENT, "the round trip left the 0055 text behind"
    finally:
        conn.close()


def test_the_prior_text_is_the_one_0055_wrote():
    """The downgrade restores what 0055 released, read from 0055 itself, so it cannot drift."""
    released = _migration("0055")
    ran: list[str] = []
    released.run = ran.append
    released.upgrade()
    statement = re.search(
        r"COMMENT ON COLUMN core\.node_merge_edge\.deleted_by_merge IS\s+((?:'(?:[^']|'')*'\s*)+);",
        "".join(ran))
    assert statement, "0055 no longer writes the comment this revision restores"
    pieces = re.findall(r"'((?:[^']|'')*)'", statement.group(1))
    assert "".join(p.replace("''", "'") for p in pieces) == _migration("0185").PRIOR_COMMENT_0055


# --- what the comment says, on a real merge ----------------------------------------------------------


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@g.GATED
def test_a_set_aside_tie_and_a_tie_between_the_pair_carry_the_same_flag(owner):
    """An AMBER case owner merges two entities joined by a RED tie, each of which holds a RED tie to the
    same third party: the tie between them would be a self-loop, and the duplicate is set aside because
    the person merging cannot read it. Both are flagged, the record counts both, the audit detail splits them."""
    from noctornal_api.merges import MergeService

    caller = s.user(owner, "AMBER", prefix=g.PREFIX)
    boss = s.user(owner, "RED", prefix=g.PREFIX)
    case_id = s.case(owner, caller)
    for uid in (caller, boss):
        s.assign(owner, case_id, uid, "CASE_OWNER")
    left = s.node(owner, case_id, boss, "sa left")
    right = s.node(owner, case_id, boss, "sa right")
    other = s.node(owner, case_id, boss, "sa other")
    between = s.edge(owner, case_id, boss, left, right, "RED")
    duplicate = s.edge(owner, case_id, boss, left, other, "RED")
    s.edge(owner, case_id, boss, right, other, "RED")
    moved = s.edge(owner, case_id, boss, left, s.node(owner, case_id, boss, "sa far"), "AMBER")

    made = g.make_client().post(
        f"/api/v1/cases/{case_id}/merges", headers=g.auth(owner, caller),
        json={"source_node_id": str(left), "target_node_id": str(right),
              "reason": "same handle, two spellings"})
    assert made.status_code == 201, made.text
    merge_id = UUID(made.json()["id"])

    flagged = {r[0]: r[1] for r in owner.execute(
        """SELECT e.edge_id, x.deleted_at IS NOT NULL FROM core.node_merge_edge e
             JOIN core.edge x ON x.id = e.edge_id
            WHERE e.merge_id = %s AND e.deleted_by_merge""", (merge_id,))}
    assert flagged == {between: True, duplicate: True}
    assert owner.execute("SELECT deleted_by_merge FROM core.node_merge_edge "
                         "WHERE merge_id = %s AND edge_id = %s",
                         (merge_id, moved)).fetchone() == (False,)

    assert MergeService(owner).get(merge_id).edges_self_loop_deleted == 2
    detail = owner.execute(
        "SELECT detail FROM audit.event WHERE action = 'NODE_MERGED' AND object_id = %s",
        (merge_id,)).fetchone()[0]
    assert (detail["edges_self_loop_deleted"], detail["edges_duplicate_folded"]) == (1, 1)
