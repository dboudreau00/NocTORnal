"""The graph read side, round three of the beta verification (2026-10-07,
Group A of the final fix list).

Seven independent verifiers re-ran the earlier review's fixes and found a
handful of places where a caller below an entity could still tell a hidden
one from a missing one. Each test here fails without its fix:

- A1: a label correction was refused with the ontology's reason when the
  value it left behind was held by an entity above the caller, and accepted
  when the value was held by nobody (`SelectorStore._types_held_by_others`).
- A2: a merge whose two entities both held a tie the caller cannot read, of
  the same type to the same third party, was refused naming the tie; the
  same merge without the hidden tie was made.
- A3: `mark_incidental` and `minimise` ignored the labels of a conversation
  and answered a random id with a 404.
- A4, A5: a 409 on a merged node and on a reversal named an entity and a
  merge the caller cannot read.
- A6: `POST /selectors` stored and returned the password of a URL.
- A7: `url:login:password`, a login without an `@`, was taken verbatim.

Everything runs through the real route as the request role and is seeded as
the owner, as `review_g42_support` does.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

CL = g.CLAIM | {"rationale": "g54 correction"}


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


# --- A1: a label correction is no oracle over a value held above the caller --

def _selector_entity(client, w, uid, label, selector_type=None):
    body = {"node_type": "SELECTOR", "label": label, "classification": "AMBER",
            "assertion": CL}
    if selector_type is not None:
        body["selector_type"] = selector_type
    r = client.post(w.url("/nodes"), headers=w.headers(uid), json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _correct_label(client, w, uid, node, label):
    return client.patch(w.url(f"/graph/nodes/{node}"), headers=w.headers(uid),
                        json={"label": label, "assertion": CL})


def test_a_label_correction_does_not_tell_a_value_held_above_the_caller_from_a_free_one(
        owner, client):
    from noctornal_api.selectors import SelectorStore
    w = g.World(owner, "NONE")
    red = w.node("g54 red phone holder", "RED")
    walled = s.node(owner, w.case_id, w.boss, "g54 compartment phone holder",
                    "AMBER", ("G54X",))
    store = SelectorStore(owner)
    store.record(case_id=w.case_id, selector_type="PHONE",
                 raw_value="+15551230001", node_id=red)
    store.record(case_id=w.case_id, selector_type="PHONE",
                 raw_value="+15551230002", node_id=walled)

    answers = {}
    for kind, value in (("held RED", "+15551230001"),
                        ("held RED, spaced", "+1 555 123 0001"),
                        ("held in a compartment", "+15551230002"),
                        ("held by nobody", "+15551239999")):
        node = _selector_entity(client, w, w.analyst, value)
        answers[kind] = g.answer(_correct_label(client, w, w.analyst, node,
                                                "xyz"))
    assert set(answers.values()) == {(200, None)}, answers


def test_a_label_correction_is_still_refused_where_the_holder_is_readable(
        owner, client):
    """The check this fix narrows, kept: a duplicate of a value an entity
    the caller CAN read holds is validated as that entity is, and the reason
    names the type (graph-selector-index-drift)."""
    w = g.World(owner, "NONE")
    first = _selector_entity(client, w, w.analyst, "+15551230003", "PHONE")
    again = _selector_entity(client, w, w.analyst, "+15551230003")
    for node in (first, again):
        r = _correct_label(client, w, w.analyst, node, "xyz")
        assert r.status_code == 400, (node, r.text)
        assert "PHONE" in r.json()["detail"], r.text


# --- A2: a merge over a tie the merger cannot read ---------------------------

def _merge(client, w, uid, source, target):
    return client.post(
        w.url("/merges"), headers=w.headers(uid),
        json={"source_node_id": str(source), "target_node_id": str(target),
              "reason": "same operator behind both"})


def _tie(owner, edge):
    """(source, target, retired) of a tie as it is stored."""
    return owner.execute(
        "SELECT src_node_id, dst_node_id, deleted_at IS NOT NULL "
        "FROM core.edge WHERE id = %s", (edge,)).fetchone()


def _merged(owner, node) -> bool:
    return owner.execute("SELECT merged_into_id IS NOT NULL FROM core.node "
                         "WHERE id = %s", (node,)).fetchone()[0]


def test_a_merge_over_a_hidden_duplicate_tie_is_made_as_one_over_no_tie_and_is_reversible(
        owner, client):
    """Two entities each held a RED tie of one type to the same visible third
    party. The merge was refused, naming the type, to an AMBER lead, and a
    merge with no hidden tie was made: the refusal was the tell. The
    duplicate is now set aside, recorded as the merge's own and given back by
    its reversal."""
    w = g.World(owner)
    control_a, control_b = w.node("g54 control a"), w.node("g54 control b")
    third = w.node("g54 shared contact")
    w.edge(control_a, third, "AMBER")
    assert _merge(client, w, w.lead, control_a, control_b).status_code == 201

    source, target = w.node("g54 source"), w.node("g54 target")
    kept, set_aside = (w.edge(target, third, "RED"),
                       w.edge(source, third, "RED"))
    r = _merge(client, w, w.lead, source, target)
    assert r.status_code == 201, r.text
    assert str(third) not in r.text and "VOUCHED_FOR" not in r.text
    assert _merged(owner, source)
    assert _tie(owner, kept) == (target, third, False)
    assert _tie(owner, set_aside) == (source, third, True)
    assert owner.execute(
        "SELECT deleted_by_merge FROM core.node_merge_edge WHERE merge_id = %s "
        "AND edge_id = %s", (r.json()["id"], set_aside)).fetchone()[0] is True
    detail = owner.execute(
        "SELECT detail FROM audit.event WHERE object_id = %s "
        "AND action = 'NODE_MERGED'", (r.json()["id"],)).fetchone()[0]
    assert detail["edges_duplicate_folded"] == 1

    # The lead cannot read either tie and is told of neither.
    undone = client.post(w.url(f"/merges/{r.json()['id']}/reverse"),
                         headers=w.headers(w.lead), json={"reason": "wrong"})
    assert undone.status_code == 200, undone.text
    assert not _merged(owner, source)
    assert _tie(owner, kept) == (target, third, False)
    assert _tie(owner, set_aside) == (source, third, False)


def test_a_merge_over_ties_to_a_third_party_the_merger_cannot_read_is_made_too(
        owner, client):
    """The same, where the ties are AMBER and the third party is RED: the
    refusal named neither but still said that two ties to one existed."""
    w = g.World(owner)
    source, target = w.node("g54 source two"), w.node("g54 target two")
    red_third = w.node("g54 red third party", "RED")
    kept, set_aside = (w.edge(target, red_third, "AMBER"),
                       w.edge(source, red_third, "AMBER"))
    r = _merge(client, w, w.lead, source, target)
    assert r.status_code == 201, r.text
    assert _tie(owner, kept)[2] is False and _tie(owner, set_aside)[2] is True


def test_a_merge_over_a_duplicate_tie_the_merger_can_read_is_still_refused(
        owner, client):
    """Nothing is set aside that the merger could have looked at and decided
    about: the refusal that tells them what to retire stands, naming the
    third party when they can read it."""
    w = g.World(owner)
    source, target = w.node("g54 source three"), w.node("g54 target three")
    third = w.node("g54 open third party")
    w.edge(target, third, "RED")
    w.edge(source, third, "RED")
    refused = _merge(client, w, w.boss, source, target)
    assert refused.status_code == 409, refused.text
    assert "VOUCHED_FOR" in refused.json()["detail"]
    assert str(third) in refused.json()["detail"]
    assert not _merged(owner, source)


# --- A5: a reversal's refusal names a later merge only to a reader of it -----

def _reverse(client, w, uid, merge_id):
    return client.post(w.url(f"/merges/{merge_id}/reverse"),
                       headers=w.headers(uid), json={"reason": "g54 undo"})


def test_a_reversal_blocked_by_a_merge_the_caller_cannot_read_does_not_name_it(
        owner, client):
    """The lead merges A into B; the boss merges B into a RED entity. The
    lead's reversal of the first is refused until the second is reversed, and
    the refusal named the second's id, which the ledger hides from them."""
    w = g.World(owner, "NONE")
    red = w.node("g54 red survivor", "RED")
    a, b, d = w.node("g54 a"), w.node("g54 b"), w.node("g54 d")
    w.edge(a, d)
    first = _merge(client, w, w.lead, a, b)
    assert first.status_code == 201, first.text
    hidden = _merge(client, w, w.boss, b, red)
    assert hidden.status_code == 201, hidden.text

    refused = _reverse(client, w, w.lead, first.json()["id"])
    assert refused.status_code == 409, refused.text
    assert hidden.json()["id"] not in refused.text
    assert "later merge" in refused.json()["detail"]

    # A reader of the later merge is still told which to reverse first.
    named = _reverse(client, w, w.boss, first.json()["id"])
    assert named.status_code == 409, named.text
    assert hidden.json()["id"] in named.json()["detail"]


# --- A4: curating a merged-away node does not name a survivor above the caller

def test_curating_a_node_merged_into_one_above_the_caller_does_not_name_the_survivor(
        owner, client):
    w = g.World(owner, "NONE")
    red = w.node("g54 red survivor", "RED")
    alias, plain_survivor, plain_alias = (
        w.node("g54 amber alias"), w.node("g54 amber survivor"),
        w.node("g54 amber alias two"))
    assert _merge(client, w, w.boss, alias, red).status_code == 201
    assert _merge(client, w, w.boss, plain_alias, plain_survivor
                  ).status_code == 201
    tag = client.post(w.url("/curation/tags"), headers=w.headers(w.lead),
                      json={"namespace": "g54", "name": "ns"})
    assert tag.status_code == 201, tag.text
    made = client.post(w.url("/curation/sets"), headers=w.headers(w.lead),
                       json={"name": "g54 set"})
    assert made.status_code == 201, made.text

    def attempts(node):
        return (
            client.post(w.url(f"/curation/tags/{tag.json()['id']}/nodes"),
                        headers=w.headers(w.lead), json={"node_id": str(node)}),
            client.post(w.url(f"/curation/sets/{made.json()['id']}/members"),
                        headers=w.headers(w.lead), json={"node_id": str(node)}))

    for r in attempts(alias):
        assert r.status_code == 409, r.text
        assert str(red) not in r.text
        assert "surviving node" in r.json()["detail"]
    # A survivor the caller may read is still named: nothing taken from them.
    for r in attempts(plain_alias):
        assert r.status_code == 409, r.text
        assert str(plain_survivor) in r.json()["detail"]
    # And the reader of the RED survivor is told, as before.
    named = client.post(w.url(f"/curation/tags/{tag.json()['id']}/nodes"),
                        headers=w.headers(w.boss), json={"node_id": str(alias)})
    assert named.status_code == 409 and str(red) in named.json()["detail"]


# --- A3: flagging and minimising a conversation above the caller --------------

def _conversation(owner, w, classification="RED"):
    from noctornal_api.comms import CommsService
    svc = CommsService(owner)
    conv = svc.open_conversation(
        case_id=w.case_id, platform_key="TELEGRAM",
        provenance_class="OPEN_GROUP", external_ref=f"g54-{uuid4().hex[:8]}",
        classification=classification)
    for n in range(3):
        svc.add_message(conv, sender_handle=f"@member{n}", body=f"message {n}")
    return conv


def test_flagging_or_minimising_a_conversation_above_the_caller_is_one_404_and_does_nothing(
        owner, client):
    w = g.World(owner, "NONE")
    red = _conversation(owner, w)

    def flag(uid, conv):
        return client.post(
            w.url(f"/comms/conversations/{conv}/incidental"),
            headers=w.headers(uid), json={"handle": "@member1"})

    def minimise(uid, conv):
        return client.post(
            w.url(f"/comms/conversations/{conv}/minimise"),
            headers=w.headers(uid), json={"authority": "g54 closure order"})

    for who in (w.analyst, w.lead):
        random = uuid4()
        assert g.answer(flag(who, red)) == g.answer(flag(who, random)) == (
            404, "no such conversation in this case")
    assert g.answer(minimise(w.lead, red)) == g.answer(
        minimise(w.lead, uuid4())) == (404, "no such conversation in this case")
    assert owner.execute(
        "SELECT is_incidental FROM comms.participant WHERE conversation_id = %s "
        "AND observed_handle = '@member1'", (red,)).fetchone()[0] is False
    assert s.count(owner, "SELECT count(*) FROM comms.message WHERE "
                          "conversation_id = %s AND body IS NOT NULL",
                   (red,)) == 3

    # Someone cleared for the conversation still does both.
    assert flag(w.boss, red).status_code == 200
    assert owner.execute(
        "SELECT is_incidental FROM comms.participant WHERE conversation_id = %s "
        "AND observed_handle = '@member1'", (red,)).fetchone()[0] is True
    done = minimise(w.boss, red)
    assert done.status_code == 200, done.text
    assert done.json()["bodies_dropped"] == 3


# --- A6: POST /selectors keeps no password -------------------------------------

def test_recording_a_link_that_carries_a_password_is_refused_and_stores_nothing(
        owner, client):
    """`record()` redacted a URL's userinfo and token on the machine paths;
    `record_for_reader`, the route's, did neither, and answered with the
    password in `raw_value`."""
    from noctornal_api.selectors import CREDENTIAL_REFUSAL
    w = g.World(owner, "NONE")
    secret = "Zq9Pass7"
    for kind, value in (
            ("URL", f"https://alice:{secret}@mail.bank.example/login"),
            ("SOCIAL_URL", f"https://bob:{secret}@social.example/u/bob"),
            ("URL", f"https://api.example/v1/items?api_key={secret}"),
            ("URL", f"https://y.example/login:carol:{secret}")):
        r = client.post(w.url("/selectors"), headers=w.headers(w.analyst),
                        json={"selector_type": kind, "raw_value": value})
        assert r.status_code == 400, (value, r.text)
        assert r.json()["detail"] == CREDENTIAL_REFUSAL, r.text
        assert secret not in r.text
    assert s.count(owner, "SELECT count(*) FROM core.selector WHERE case_id = %s "
                          "AND raw_value LIKE %s",
                   (w.case_id, f"%{secret}%")) == 0

    clean = client.post(w.url("/selectors"), headers=w.headers(w.analyst),
                        json={"selector_type": "URL",
                              "raw_value": "https://mail.bank.example/login"})
    assert clean.status_code == 201, clean.text
    assert clean.json()["raw_value"] == "https://mail.bank.example/login"


# --- A7: the same shape through the entity routes ------------------------------

def test_an_entity_labelled_with_a_login_pair_without_an_address_is_refused(
        owner, client):
    from noctornal_api.selectors import CREDENTIAL_REFUSAL
    w = g.World(owner, "NONE")
    link = "https://y.example/login:carol:Zq9Pass7p"
    r = client.post(w.url("/nodes"), headers=w.headers(w.analyst), json={
        "node_type": "SELECTOR", "selector_type": "URL", "label": link,
        "classification": "AMBER", "assertion": CL})
    assert r.status_code == 400 and r.json()["detail"] == CREDENTIAL_REFUSAL, r.text
    node = _selector_entity(client, w, w.analyst, "https://y.example/login",
                            "URL")
    r = _correct_label(client, w, w.analyst, node, link)
    assert r.status_code == 400 and r.json()["detail"] == CREDENTIAL_REFUSAL, r.text
    assert owner.execute("SELECT label FROM core.node WHERE id = %s",
                         (node,)).fetchone()[0] == "https://y.example/login"
    assert s.count(owner, "SELECT count(*) FROM core.node WHERE case_id = %s "
                          "AND label LIKE %s", (w.case_id, "%Zq9Pass7p%")) == 0
