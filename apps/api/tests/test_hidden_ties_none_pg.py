"""Retiring an entity that carries a tie the caller cannot see, under each
`withheld_disclosure` setting (docs/17, "retiring an entity with a hidden tie";
owner decision, 2026-10-08).

The refusal used to be one sentence under every setting, so a case set to NONE
(migration 0030: say nothing about what is withheld) still told the caller that
a tie above them touches the entity. Under NONE it now reads as the refusal of
an act that was not done and names nothing; under PRESENCE and COUNT it is
today's sentence. Nothing is retired over a hidden tie under any of them, and
the second guard that answers in the same words (a live merge into the entity
whose merged side the caller cannot see) follows the setting too, so the two
cannot be told apart.

Through the real route as the request role (`review_g42_support`).
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

#: What a refusal under NONE must not say: a tie, a level, a lock, or that
#: anything is out of the caller's sight.
NONE_WORDS = ("tie", "clearance", "compartment", "above", "hidden", "withheld",
              "cleared")


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _retire(client, w, node):
    return client.request("DELETE", w.url(f"/graph/nodes/{node}"),
                          headers=w.headers(w.lead), json={"reason": "probe"})


def _alive(owner, table, element_id) -> bool:
    return owner.execute(
        f"SELECT deleted_at IS NULL FROM core.{table} WHERE id = %s",
        (element_id,)).fetchone()[0]


def _three_ways_to_be_refused(owner, w):
    """An entity per guard, each refused for something the caller cannot see:
    a tie above them, a tie to an entity above them, and a live merge of an
    entity above them into it. Returns (entity, the ties that must survive)."""
    amber2, amber3 = w.node("g78 amber two"), w.node("g78 amber three")
    above_tie = w.edge(amber2, amber3, "RED")

    amber, red = w.node("g78 amber"), w.node("g78 red", "RED")
    low_tie = w.edge(amber, red, "AMBER")

    hidden_red, keeper = w.node("g78 merged red", "RED"), w.node("g78 keeper")
    contact = w.node("g78 contact")
    visible_tie = w.edge(contact, keeper)
    # A RED entity merged into an AMBER survivor is refused as a merge, so the
    # ledger row is seeded as the owner: the guard reads every merge whatever
    # its labels, which is why it runs on a system connection.
    owner.execute(
        "INSERT INTO core.node_merge (case_id, source_node_id, target_node_id, "
        "reason, merged_at, merged_by) VALUES (%s, %s, %s, 'g78 seeded', now(), %s)",
        (w.case_id, hidden_red, keeper, w.boss))
    return {"tie above the caller": (amber2, above_tie),
            "tie to an entity above the caller": (amber, low_tie),
            "merge of an entity above the caller": (keeper, visible_tie)}


def test_under_none_every_refusal_reads_alike_and_names_nothing(owner, client):
    w = g.World(owner, withheld="NONE")
    cases = _three_ways_to_be_refused(owner, w)

    answers = {}
    for name, (entity, tie) in cases.items():
        refused = _retire(client, w, entity)
        assert refused.status_code == 400, (name, refused.text)
        answers[name] = g.answer(refused)
        sentence = refused.json()["detail"].lower()
        for word in NONE_WORDS:
            assert word not in sentence, (name, word, sentence)
        assert "edges_retired" not in refused.text
        # Nothing was retired over the tie, and the entity is still there.
        assert _alive(owner, "node", entity) and _alive(owner, "edge", tie), name

    from noctornal_api.graph import HIDDEN_TIES_REFUSAL, HIDDEN_TIES_REFUSAL_NONE
    assert set(answers.values()) == {(400, HIDDEN_TIES_REFUSAL_NONE)}, answers
    assert HIDDEN_TIES_REFUSAL_NONE != HIDDEN_TIES_REFUSAL


@pytest.mark.parametrize("mode", ["PRESENCE", "COUNT"])
def test_under_presence_and_count_the_refusal_is_the_sentence_it_always_was(
        owner, client, mode):
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL
    w = g.World(owner, withheld=mode)
    for name, (entity, tie) in _three_ways_to_be_refused(owner, w).items():
        refused = _retire(client, w, entity)
        assert g.answer(refused) == (400, HIDDEN_TIES_REFUSAL), (name, refused.text)
        assert _alive(owner, "node", entity) and _alive(owner, "edge", tie), name


def test_the_sentence_follows_the_setting_as_it_is_changed(owner, client):
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL
    w = g.World(owner, withheld="COUNT")
    amber2, amber3 = w.node("g78 a"), w.node("g78 b")
    w.edge(amber2, amber3, "RED")

    assert g.answer(_retire(client, w, amber2))[1] == HIDDEN_TIES_REFUSAL
    w.disclose("NONE")
    under_none = g.answer(_retire(client, w, amber2))[1]
    assert under_none != HIDDEN_TIES_REFUSAL
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL_NONE
    assert under_none == HIDDEN_TIES_REFUSAL_NONE
    w.disclose("PRESENCE")
    assert g.answer(_retire(client, w, amber2))[1] == HIDDEN_TIES_REFUSAL


def test_a_setting_that_cannot_be_read_is_none(owner):
    """An unknown case, or an unknown mode, says nothing: fail closed."""
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL_NONE, hidden_ties_refusal
    assert hidden_ties_refusal(owner, uuid4()) == HIDDEN_TIES_REFUSAL_NONE


def test_under_none_what_the_caller_may_retire_is_still_retired(owner, client):
    """The refusal takes nothing away from a legitimate caller: the cleared
    owner retires the entity whole, and the caller retires one whose ties they
    can all read."""
    w = g.World(owner, withheld="NONE")
    amber, red = w.node("g78 amber"), w.node("g78 red", "RED")
    w.edge(amber, red, "AMBER")
    assert _retire(client, w, amber).status_code == 400

    cleared = client.request("DELETE", w.url(f"/graph/nodes/{amber}"),
                             headers=w.headers(w.boss), json={"reason": "retire"})
    assert cleared.status_code == 200 and cleared.json()["edges_retired"] == 1

    plain, other = w.node("g78 plain"), w.node("g78 other")
    w.edge(plain, other)
    own = _retire(client, w, plain)
    assert own.status_code == 200 and own.json()["edges_retired"] == 1


def test_the_service_answers_the_same_under_the_request_role(owner):
    """The guard counts on a system connection and the sentence is read as a
    lock fact: both work for a connection that is row-filtered, which is what
    the route hands the service in production."""
    from noctornal_api.graph import (
        HIDDEN_TIES_REFUSAL_NONE, GraphWriteError, GraphWriteService)
    w = g.World(owner, withheld="NONE")
    amber2, amber3 = w.node("g78 a"), w.node("g78 b")
    w.edge(amber2, amber3, "RED")
    _, raw = s.session(owner, w.lead)
    app = s.app_conn(raw)
    try:
        with pytest.raises(GraphWriteError) as raised:
            GraphWriteService(app).soft_delete_node(
                amber2, case_id=w.case_id, deleted_by=w.lead, at=s.now(),
                clearance="AMBER", compartments=frozenset())
    finally:
        app.close()
    assert str(raised.value) == HIDDEN_TIES_REFUSAL_NONE
    assert _alive(owner, "node", amber2)
