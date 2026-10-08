"""A persona carries no real name (invariant 2; docs/17, "`real_name` on an
identity").

`IDENTITY` is a handle that was observed and `PERSON` is a human that was
assessed; they meet only through a reversible `ATTRIBUTED_TO` tie. The schema
cannot keep a name off a persona, because `core.node.attrs` is free-form jsonb,
so the graph service, the one writer, refuses the key at creation and at
correction. A PERSON may carry one.
"""
from __future__ import annotations

import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

CLAIM = g.CLAIM


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _assertion(uid):
    from noctornal_api.graph import AssertionInput
    return AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                          reliability="A", credibility="1", confidence="HIGH")


def _create(owner, w, node_type, attrs, label="g78 entity"):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(owner).create_node(
        case_id=w.case_id, node_type=node_type, label=label, created_by=w.boss,
        assertion=_assertion(w.boss), attrs=attrs)


def _correct(owner, w, node_id, **kw):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(owner).update_node(
        node_id, case_id=w.case_id, assertion=_assertion(w.boss), **kw)


def _rows(owner, w) -> tuple[int, int]:
    """(nodes, claims) the case holds: a refused write leaves neither."""
    return (owner.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                          (w.case_id,)).fetchone()[0],
            owner.execute("SELECT count(*) FROM core.assertion WHERE case_id = %s",
                          (w.case_id,)).fetchone()[0])


def _attrs(owner, node_id) -> dict:
    return owner.execute("SELECT attrs FROM core.node WHERE id = %s",
                         (node_id,)).fetchone()[0]


REFUSED_SPELLINGS = [
    {"real_name": "Alex Morgan"},
    {"Real Name": "Alex Morgan"},
    {"real-name": "Alex Morgan"},
    {"realName": "Alex Morgan"},
    {"REAL_NAME": "Alex Morgan"},
    # Full-width letters, which fold to the same word.
    {"".join(map(chr, (0xFF52, 0xFF45, 0xFF41, 0xFF4C, 0xFF3F, 0xFF4E,
                       0xFF41, 0xFF4D, 0xFF45))): "Alex Morgan"},
    {"country": "NL", "real_name": None},
    {"profile": {"real_name": "Alex Morgan"}},
    {"aliases": [{"handle": "x"}, {"real_name": "Alex Morgan"}]},
]


@pytest.mark.parametrize("attrs", REFUSED_SPELLINGS)
def test_a_persona_is_refused_a_real_name_at_creation(owner, attrs):
    from noctornal_api.graph import GraphWriteError
    w = g.World(owner)
    before = _rows(owner, w)
    with pytest.raises(GraphWriteError) as refused:
        _create(owner, w, "IDENTITY", attrs)
    from noctornal_api.graph import REAL_NAME_REFUSAL
    assert str(refused.value) == REAL_NAME_REFUSAL
    assert "Alex" not in str(refused.value)
    assert _rows(owner, w) == before


def test_what_is_not_a_real_name_is_still_an_attribute_of_a_persona(owner):
    w = g.World(owner)
    ok = {"platform": "forum", "handle_since": "2024", "real_estate_name": "n/a",
          "surname_hint": "unknown", "profile": {"display_name": "Skua"},
          "aliases": [{"handle": "skua2"}]}
    node = _create(owner, w, "IDENTITY", ok)
    assert _attrs(owner, node) == ok
    assert _create(owner, w, "IDENTITY", None, label="g78 bare")
    assert _create(owner, w, "IDENTITY", {}, label="g78 empty")


def test_a_person_may_carry_a_real_name(owner):
    """The name belongs to the assessed human, which is the point of the split."""
    w = g.World(owner)
    node = _create(owner, w, "PERSON", {"real_name": "Alex Morgan"})
    assert _attrs(owner, node) == {"real_name": "Alex Morgan"}
    changed = _correct(owner, w, node, attrs={"real_name": "Alexandra Morgan"})
    assert changed is None
    assert _attrs(owner, node) == {"real_name": "Alexandra Morgan"}


@pytest.mark.parametrize("attrs", REFUSED_SPELLINGS)
def test_a_correction_cannot_put_a_real_name_on_a_persona(owner, attrs):
    from noctornal_api.graph import GraphWriteError
    w = g.World(owner)
    node = _create(owner, w, "IDENTITY", {"platform": "forum"}, label="g78 handle")
    before = _rows(owner, w)
    with pytest.raises(GraphWriteError) as refused:
        _correct(owner, w, node, label="g78 handle renamed", attrs=attrs)
    from noctornal_api.graph import REAL_NAME_REFUSAL
    assert str(refused.value) == REAL_NAME_REFUSAL
    # The whole correction is refused: the label did not move, the attributes
    # are as they were, and no claim was recorded for a change that was not made.
    assert owner.execute("SELECT label FROM core.node WHERE id = %s",
                         (node,)).fetchone()[0] == "g78 handle"
    assert _attrs(owner, node) == {"platform": "forum"}
    assert _rows(owner, w) == before


def test_a_real_name_written_before_the_rule_can_be_taken_off(owner):
    """Rows from before are not rewritten, and the way to clean one is the
    correction the product already has: attributes that leave it out."""
    w = g.World(owner)
    node = _create(owner, w, "IDENTITY", {"platform": "forum"})
    owner.execute("UPDATE core.node SET attrs = %s WHERE id = %s",
                  ('{"platform": "forum", "real_name": "Alex Morgan"}', node))
    _correct(owner, w, node, attrs={"platform": "forum"})
    assert _attrs(owner, node) == {"platform": "forum"}
    # And a correction that leaves the old key in is refused like any other.
    from noctornal_api.graph import GraphWriteError
    with pytest.raises(GraphWriteError):
        _correct(owner, w, node, attrs={"platform": "forum",
                                        "real_name": "Alex Morgan"})


def test_the_routes_refuse_it_in_the_graph_services_words(owner, client):
    w = g.World(owner)
    lead = w.headers(w.lead)

    refused = client.post(w.url("/nodes"), headers=lead, json={
        "node_type": "IDENTITY", "label": "g78 handle",
        "attrs": {"real_name": "Alex Morgan"}, "assertion": CLAIM})
    assert refused.status_code == 400, refused.text
    from noctornal_api.graph import REAL_NAME_REFUSAL
    assert g.answer(refused) == (400, REAL_NAME_REFUSAL)
    assert owner.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                         (w.case_id,)).fetchone()[0] == 0

    made = client.post(w.url("/nodes"), headers=lead, json={
        "node_type": "IDENTITY", "label": "g78 handle",
        "attrs": {"platform": "forum"}, "assertion": CLAIM})
    assert made.status_code == 201, made.text
    node = made.json()["id"]
    patched = client.patch(w.url(f"/graph/nodes/{node}"), headers=lead, json={
        "attrs": {"real_name": "Alex Morgan"}, "assertion": CLAIM})
    assert g.answer(patched) == (400, REAL_NAME_REFUSAL)
    assert _attrs(owner, node) == {"platform": "forum"}

    # A person takes the name through the same routes.
    person = client.post(w.url("/nodes"), headers=lead, json={
        "node_type": "PERSON", "label": "Alex Morgan",
        "attrs": {"real_name": "Alex Morgan"}, "assertion": CLAIM})
    assert person.status_code == 201, person.text
    fixed = client.patch(w.url(f"/graph/nodes/{person.json()['id']}"), headers=lead,
                         json={"attrs": {"real_name": "Alexandra Morgan"},
                               "assertion": CLAIM})
    assert fixed.status_code == 200, fixed.text


def test_an_accepted_proposal_cannot_smuggle_one_in(owner, client):
    """Triage writes through the same service: a machine's suggestion that
    names a persona with a real name is refused when a person accepts it, and
    stays in the queue."""
    from noctornal_api.proposals import ProposalStore
    w = g.World(owner)
    pid = ProposalStore(owner).propose(
        case_id=w.case_id, kind="NODE", origin="g78_test_v1",
        payload={"node_type": "IDENTITY", "label": "g78 proposed",
                 "attrs": {"real_name": "Alex Morgan"}},
        rationale="a machine's suggestion", score=0.5)
    refused = client.post(w.url(f"/proposals/{pid}/accept"),
                          headers=w.headers(w.lead), json={})
    assert refused.status_code == 409, refused.text
    from noctornal_api.graph import REAL_NAME_REFUSAL
    assert REAL_NAME_REFUSAL in refused.json()["detail"]
    assert "Alex" not in refused.text
    assert owner.execute("SELECT state FROM collect.proposal WHERE id = %s",
                         (pid,)).fetchone()[0] == "PROPOSED"
    assert s.count(owner, "SELECT count(*) FROM core.node WHERE case_id = %s",
                   (w.case_id,)) == 0
