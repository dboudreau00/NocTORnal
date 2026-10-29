"""A merge notice counts only the ties the case owner may read.

The notice is labelled with the case and the two merged entities, so an owner
cleared for those reads it. A tie between the two, or of the source, may sit
above the owner. The merge still re-points or retires such a tie, and the audit
row and the ledger keep the full count, but the notice must not tell the owner
that it exists or how many there were. The summary line may be emailed.
"""
from __future__ import annotations

import pytest

import graph_visibility_support as g
import rls_support as s

pytestmark = g.GATED


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _world(owner, keeper_clearance: str):
    """A case owned by `keeper`, merged by an AMBER case owner, with RED ties
    recorded by a RED colleague."""
    keeper = s.user(owner, keeper_clearance, prefix=g.PREFIX)
    caller = s.user(owner, "AMBER", prefix=g.PREFIX)
    boss = s.user(owner, "RED", prefix=g.PREFIX)
    case_id = s.case(owner, keeper)
    for uid in (keeper, caller, boss):
        s.assign(owner, case_id, uid, "CASE_OWNER")
    left = s.node(owner, case_id, boss, "mn left")
    right = s.node(owner, case_id, boss, "mn right")
    other = s.node(owner, case_id, boss, "mn other")
    visible = s.node(owner, case_id, boss, "mn visible")
    far = s.node(owner, case_id, boss, "mn far")
    # The tie between the two, a pair to the same third party that the merge
    # folds, and a tie that moves: all RED. One AMBER tie that moves and
    # anyone here may read.
    for src, dst in ((left, right), (left, other), (right, other)):
        s.edge(owner, case_id, boss, src, dst, "RED")
    s.edge(owner, case_id, boss, left, far, "RED")
    s.edge(owner, case_id, boss, left, visible, "AMBER")
    return keeper, caller, case_id, left, right


def _merge(client, owner, caller, case_id, source, target):
    made = client.post(
        f"/api/v1/cases/{case_id}/merges", headers=g.auth(owner, caller),
        json={"source_node_id": str(source), "target_node_id": str(target),
              "reason": "same handle, two spellings"})
    assert made.status_code == 201, made.text
    return made.json()["id"]


def _notice(owner, keeper):
    rows = owner.execute(
        """SELECT classification::text, summary, body FROM notify.notification
            WHERE recipient_id = %s AND kind = 'MERGE_PERFORMED'""",
        (keeper,)).fetchall()
    assert len(rows) == 1
    return rows[0]


def test_an_amber_owner_is_not_told_of_red_ties_the_merge_touched(owner, client):
    from noctornal_api.merges import MergeService
    keeper, caller, case_id, left, right = _world(owner, "AMBER")
    merge_id = _merge(client, owner, caller, case_id, left, right)

    system = MergeService(owner).get(merge_id)
    assert system.edges_repointed == 2
    assert system.edges_self_loop_deleted == 2

    classification, summary, body = _notice(owner, keeper)
    assert classification == "AMBER"
    assert "re-pointed 1 relationship." in summary
    assert "moving 1 relationship." in body
    assert "BETWEEN the two" not in body
    assert "could not read" not in body


def test_a_red_owner_is_told_of_every_tie(owner, client):
    """The counts follow the owner's labels, not a blanket cut."""
    keeper, caller, case_id, left, right = _world(owner, "RED")
    _merge(client, owner, caller, case_id, left, right)

    _, summary, body = _notice(owner, keeper)
    assert "re-pointed 2 relationships." in summary
    assert "A further 1 relationship BETWEEN the two was destroyed" in body
    assert "A further 1 relationship duplicated a tie" in body
