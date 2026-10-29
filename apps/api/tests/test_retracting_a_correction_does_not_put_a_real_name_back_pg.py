"""Withdrawing a correction does not put a real name back on a persona.

A persona written before the graph refused `real_name` is cleaned by a
correction that leaves the key out. That correction records the attributes it
replaced, name included. Retracting it puts the supported attributes back, and
when nothing live supports them that is the recorded prior value. The restore
must refuse the name as creation and correction do, and leave the cleaned
attributes in place.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import graph_visibility_support as g

pytestmark = g.GATED


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


def _assertion(uid, **kw):
    from noctornal_api.graph import AssertionInput
    return AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                          reliability="A", credibility="1", confidence="HIGH",
                          **kw)


def _attrs(owner, node_id) -> dict:
    return owner.execute("SELECT attrs FROM core.node WHERE id = %s",
                         (node_id,)).fetchone()[0]


def test_retracting_the_cleaning_correction_leaves_the_name_off(owner):
    from noctornal_api.graph import GraphWriteService
    w = g.World(owner)
    svc = GraphWriteService(owner)
    node = svc.create_node(
        case_id=w.case_id, node_type="IDENTITY", label="rn handle",
        created_by=w.boss, assertion=_assertion(w.boss),
        attrs={"platform": "forum"})
    owner.execute("UPDATE core.node SET attrs = %s WHERE id = %s",
                  ('{"platform": "forum", "real_name": "Alex Morgan"}', node))

    cleaned = {"platform": "forum"}
    svc.update_node(node, case_id=w.case_id, attrs=cleaned,
                    assertion=_assertion(w.boss, claim_path="attrs",
                                         claim_value={"attrs": cleaned}))
    assert _attrs(owner, node) == cleaned

    correction = owner.execute(
        """SELECT id FROM core.assertion
            WHERE node_id = %s AND retracted_at IS NULL
              AND claim_value ? 'attrs'
            ORDER BY recorded_at DESC LIMIT 1""", (node,)).fetchone()[0]
    restoration = svc.retract_assertion(
        correction, retracted_by=w.boss, reason="the wrong draft", at=datetime.now(timezone.utc))

    assert _attrs(owner, node) == cleaned
    # The retraction stands; the caller is told the attributes were not put back.
    assert "attrs" in restoration.unknown
    assert owner.execute("SELECT retracted_at IS NOT NULL FROM core.assertion "
                         "WHERE id = %s", (correction,)).fetchone()[0]


def test_a_person_still_gets_its_name_back(owner):
    """The refusal is for personas only: an assessed person may carry a name."""
    from noctornal_api.graph import GraphWriteService
    w = g.World(owner)
    svc = GraphWriteService(owner)
    node = svc.create_node(
        case_id=w.case_id, node_type="PERSON", label="rn person",
        created_by=w.boss, assertion=_assertion(w.boss),
        attrs={"real_name": "Alex Morgan"})
    changed = {"real_name": "Alexandra Morgan"}
    svc.update_node(node, case_id=w.case_id, attrs=changed,
                    assertion=_assertion(w.boss, claim_path="attrs",
                                         claim_value={"attrs": changed}))
    correction = owner.execute(
        """SELECT id FROM core.assertion
            WHERE node_id = %s AND retracted_at IS NULL
              AND claim_value ? 'attrs'
            ORDER BY recorded_at DESC LIMIT 1""", (node,)).fetchone()[0]
    svc.retract_assertion(correction, retracted_by=w.boss, reason="wrong",
                          at=datetime.now(timezone.utc))
    assert _attrs(owner, node) == {"real_name": "Alex Morgan"}
