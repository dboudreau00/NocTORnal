"""What a reader is told about what they cannot see (beta review, 2026-10-03).

- rls-9: the node-set member list said exactly how many hidden entities each
  working set held, whatever the case's withheld_disclosure said.
- graph-coparticipation-ignores-withheld-none: the co-participation network
  said how many participants resolved to an entity the reader cannot see, and
  with the filters narrowed it to one room, whatever the setting said.
- http_ui-008: a comms binding took any node id (another case's, one above the
  caller, an unknown one as a 500).
- http_ui-016: for a change to an element above the caller the gate answered
  403 "missing permission", and for an unknown id 404, so a caller holding a
  leaked id could confirm it. One answer now, the audit row kept.

NONE says nothing, PRESENCE says whether, COUNT says how many: the graph's
own rule (`projections.Withheld`), here by `element_gate.withheld_notice`.
"""
from __future__ import annotations

from uuid import uuid4

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


# --- the node-set member list (rls-9) ---------------------------------------

def _set_with(owner, w, nodes):
    from noctornal_api.curation import NodeSetService
    sid = NodeSetService(owner).create_set(case_id=w.case_id, name="g42 set",
                                           created_by=w.boss)
    for n in nodes:
        NodeSetService(owner).add_member(sid, n)
    return sid


def test_a_working_set_says_what_it_withholds_as_the_case_allows(owner, client):
    w = g.World(owner)
    visible = w.node("g42 amber")
    sid = _set_with(owner, w, [visible, w.node("g42 red 1", "RED"),
                               w.node("g42 red 2", "RED")])

    def members(uid, mode):
        w.disclose(mode)
        r = client.get(w.url(f"/curation/sets/{sid}/members"),
                       headers=w.headers(uid))
        assert r.status_code == 200, r.text
        return r.json()

    none = members(w.analyst, "NONE")
    assert [m["node_id"] for m in none["members"]] == [str(visible)]
    assert set(none) == {"set_id", "members", "merged_away"}
    presence = members(w.analyst, "PRESENCE")
    assert (presence["incomplete"], presence["mode"]) == (True, "PRESENCE")
    assert "withheld" not in presence
    count = members(w.analyst, "COUNT")
    assert (count["incomplete"], count["mode"], count["withheld"]) == (
        True, "COUNT", 2)
    # A reader shown every member is told nothing was withheld, under COUNT.
    assert members(w.boss, "COUNT")["withheld"] == 0
    assert set(members(w.boss, "NONE")) == {"set_id", "members", "merged_away"}


# --- co-participation (graph-coparticipation-ignores-withheld-none) ----------

def _room(owner, w):
    a1, a2 = w.node("g42 a1"), w.node("g42 a2")
    hidden = w.node("g42 red hidden", "RED")
    conv = owner.execute(
        "INSERT INTO comms.conversation (case_id, platform_key, provenance_class, "
        "is_group) VALUES (%s, 'XMPP', 'OPEN_GROUP', true) RETURNING id",
        (w.case_id,)).fetchone()[0]
    for handle, node in (("a1", a1), ("a2", a2), ("hidden", hidden)):
        owner.execute(
            "INSERT INTO comms.participant (conversation_id, observed_handle, "
            "identity_node_id) VALUES (%s, %s, %s)", (conv, handle, node))
    return conv


def test_co_participation_counts_hidden_participants_only_as_the_case_allows(
        owner, client):
    w = g.World(owner)
    _room(owner, w)

    def coverage(mode):
        w.disclose(mode)
        r = client.get(w.url("/comms/co-participation"),
                       headers=w.headers(w.analyst))
        assert r.status_code == 200, r.text
        return r.json()["coverage"]

    none = coverage("NONE")
    assert "participants_excluded_not_visible" not in none
    assert "withheld" not in none
    presence = coverage("PRESENCE")
    assert presence["withheld"] == {"incomplete": True, "mode": "PRESENCE"}
    assert "participants_excluded_not_visible" not in presence
    count = coverage("COUNT")
    assert count["participants_excluded_not_visible"] == 1
    assert count["withheld"] == {"incomplete": True, "mode": "COUNT",
                                 "participants": 1}


def test_an_oversized_rooms_projectable_count_is_a_count_too():
    from noctornal_api.http.routers.comms import _disclose_hidden_participants

    def out():
        return {"coverage": {
            "participants_excluded_not_visible": 3,
            "oversized": [{"conversation_id": "c", "participants": 90,
                           "projectable_participants": 87}]}}

    none, presence, count = out(), out(), out()
    _disclose_hidden_participants(none, "NONE")
    _disclose_hidden_participants(presence, "PRESENCE")
    _disclose_hidden_participants(count, "COUNT")
    assert none["coverage"] == {"oversized": [
        {"conversation_id": "c", "participants": 90}]}
    assert presence["coverage"]["oversized"] == none["coverage"]["oversized"]
    assert presence["coverage"]["withheld"] == {"incomplete": True,
                                                "mode": "PRESENCE"}
    assert count["coverage"]["oversized"][0]["projectable_participants"] == 87
    assert count["coverage"]["participants_excluded_not_visible"] == 3


# --- comms binding (http_ui-008) ---------------------------------------------

def _bind(client, w, uid, node, observed=None):
    return client.post(w.url("/comms/bindings"), headers=w.headers(uid), json={
        "platform_key": "TELEGRAM", "observed": observed or f"@g42_{uuid4().hex[:8]}",
        "identity_node_id": str(node)})


def test_a_binding_names_an_entity_of_this_case_the_caller_may_read(owner, client):
    w = g.World(owner)
    mine = w.node("g42 mine")
    hidden = w.node("g42 hidden", "RED")
    other_owner = s.user(owner, "RED", prefix=g.PREFIX)
    other_case = s.case(owner, other_owner, "RED")
    foreign = s.node(owner, other_case, other_owner, "g42 foreign", "RED")

    refused = [g.answer(_bind(client, w, w.analyst, named))
               for named in (hidden, foreign, uuid4())]
    assert refused == [(404, "no such node in this case")] * 3
    assert owner.execute("SELECT count(*) FROM comms.channel_binding "
                         "WHERE case_id = %s", (w.case_id,)).fetchone()[0] == 0

    ok = _bind(client, w, w.analyst, mine)
    assert ok.status_code == 201, ok.text
    assert owner.execute(
        "SELECT identity_node_id FROM comms.channel_binding WHERE case_id = %s",
        (w.case_id,)).fetchone()[0] == mine
    # The cleared owner binds the RED entity, as before.
    assert _bind(client, w, w.boss, hidden).status_code == 201


# --- hidden is missing (http_ui-016) -------------------------------------------

def _denials(owner, uid) -> int:
    return owner.execute("SELECT count(*) FROM audit.event WHERE action = "
                         "'AUTHZ_DENIED' AND actor_id = %s", (uid,)).fetchone()[0]


def test_a_change_to_an_entity_above_the_caller_reads_as_a_missing_entity(
        owner, client):
    w = g.World(owner)
    hidden = w.node("g42 hidden", "RED")
    tag = client.post(w.url("/curation/tags"), headers=w.headers(w.boss),
                      json={"namespace": "g42", "name": "t"}).json()["id"]
    working_set = client.post(w.url("/curation/sets"), headers=w.headers(w.boss),
                              json={"name": "g42 set"}).json()["id"]
    H = w.headers(w.analyst)
    routes = {
        "add a claim": lambda i: client.post(
            w.url(f"/nodes/{i}/assertions"), headers=H, json=CLAIM),
        "correct": lambda i: client.patch(
            w.url(f"/graph/nodes/{i}"), headers=H,
            json={"label": "g42 x", "assertion": CLAIM}),
        "retire": lambda i: client.request(
            "DELETE", w.url(f"/graph/nodes/{i}"), headers=H,
            json={"reason": "probe"}),
        "tag": lambda i: client.post(
            w.url(f"/curation/tags/{tag}/nodes"), headers=H,
            json={"node_id": str(i)}),
        "untag": lambda i: client.request(
            "DELETE", w.url(f"/curation/tags/{tag}/nodes/{i}"), headers=H),
        "add to a set": lambda i: client.post(
            w.url(f"/curation/sets/{working_set}/members"), headers=H,
            json={"node_id": str(i)}),
        "remove from a set": lambda i: client.request(
            "DELETE", w.url(f"/curation/sets/{working_set}/members/{i}"),
            headers=H),
    }
    for name, call in routes.items():
        before = _denials(owner, w.analyst)
        hit = call(hidden)
        recorded = _denials(owner, w.analyst) - before
        miss = call(uuid4())
        assert g.answer(hit) == g.answer(miss), name
        assert hit.status_code == 404, (name, hit.text)
        # The refusal is still on the record, as before; a missing id has none.
        assert recorded == 1, name
        assert _denials(owner, w.analyst) - before == recorded, name


def test_a_change_to_a_tie_or_claim_above_the_caller_reads_as_a_missing_one(
        owner, client):
    w = g.World(owner)
    a, b = w.node("g42 a"), w.node("g42 b")
    hidden_tie = w.edge(a, b, "RED")
    red = w.node("g42 red", "RED")
    claim = owner.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                          (red,)).fetchone()[0]
    H = w.headers(w.analyst)
    for name, call in {
        "claim on a tie": lambda i: client.post(
            w.url(f"/edges/{i}/assertions"), headers=H, json=CLAIM),
        "correct a tie": lambda i: client.patch(
            w.url(f"/graph/edges/{i}"), headers=H,
            json={"weight": 0.5, "assertion": CLAIM}),
        "retire a tie": lambda i: client.request(
            "DELETE", w.url(f"/graph/edges/{i}"), headers=H,
            json={"reason": "probe"}),
        # The analyst role lacks proposal.review: the lead holds it.
        "review a tie": lambda i: client.post(
            w.url(f"/graph/edges/{i}/review"), headers=w.headers(w.lead),
            json={"review": "DISPUTED", "note": "g42"}),
    }.items():
        assert g.answer(call(hidden_tie)) == g.answer(call(uuid4())), name
        assert call(hidden_tie).status_code == 404, name
    hit = client.post(w.url(f"/assertions/{claim}/retract"), headers=H,
                      json={"reason": "g42 probe"})
    miss = client.post(w.url(f"/assertions/{uuid4()}/retract"), headers=H,
                       json={"reason": "g42 probe"})
    assert g.answer(hit) == g.answer(miss) == (404, "no such assertion in this case")


def test_a_caller_without_the_verb_is_still_told_so_not_that_it_is_missing(
        owner, client):
    """The case's own gate asks the verb first: a read-only member is refused
    403 for a hidden entity and a missing one alike, so nothing was turned into
    a 404 that a 403 said already."""
    w = g.World(owner)
    hidden = w.node("g42 hidden", "RED")
    H = w.headers(w.reader)
    hit = client.post(w.url(f"/nodes/{hidden}/assertions"), headers=H, json=CLAIM)
    miss = client.post(w.url(f"/nodes/{uuid4()}/assertions"), headers=H, json=CLAIM)
    assert g.answer(hit) == g.answer(miss)
    assert hit.status_code == 403
