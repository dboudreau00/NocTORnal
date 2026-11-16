"""A co-participation weight carries nothing the roster does not (docs/00 decision 232).

A tie's Newman weight divides by the room's roster: every participant row of the conversation,
resolved or not, visible to the reader or not (`coparticipation.py`). The register read that as a
channel: a room of two AMBER identities and one RED one weighs 0.5 where a two-person room weighs
1.0, so an AMBER reader could difference a weight to learn that someone they cannot see is in the
room. It is not one, because the roster is not hidden. `comms.participant` carries no labels and its
row policy is its conversation's, so whoever may read a conversation may list every participant of
it (`GET /comms/contact-graph`, under the same `comms.read`). These tests hold that:

- the weight is computable from what the same reader can list, under NONE, PRESENCE and COUNT;
- it is one figure for every reader of the room: AMBER, RED, and AMBER under a case-scoped RED grant;
- it does not move when the third member of a room is unresolved, AMBER or RED;
- an oversized room is sized by the same list;
- a handle that resolves above the reader is, to the reader, an unresolved handle: drawn as one, and
  under NONE and PRESENCE counted as one, so no answer tells the two apart;
- and the premise itself: the roster has no label column and a CHILD policy, so a migration that
  labels participants fails here and the decision has to be taken again.

Dividing by the members the reader can resolve would create the channel the register feared: set
against the handles the reader can list, 1/(visible - 1) says how many of them resolve above the
reader. Every test runs the real routes as the request role and seeds as the owner
(`graph_visibility_support`).
"""
from __future__ import annotations

import json

import pytest

import graph_visibility_support as g
import rls_support as s

pytestmark = g.GATED

MODES = ("NONE", "PRESENCE", "COUNT")


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _room(owner, w, members) -> str:
    """A group conversation of the case whose participants are (handle, identity or None)."""
    conv = owner.execute(
        "INSERT INTO comms.conversation (case_id, platform_key, provenance_class, "
        "is_group) VALUES (%s, 'XMPP', 'OPEN_GROUP', true) RETURNING id",
        (w.case_id,)).fetchone()[0]
    for handle, node in members:
        owner.execute(
            "INSERT INTO comms.participant (conversation_id, observed_handle, "
            "identity_node_id) VALUES (%s, %s, %s)", (conv, handle, node))
    return str(conv)


def _read(client, w, uid, tail: str, **params) -> dict:
    r = client.get(w.url(tail), headers=w.headers(uid), params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _weight(projection: dict, a, b) -> float:
    """The weight of the one tie between entities `a` and `b`."""
    pair = {f"node:{a}", f"node:{b}"}
    ties = [e for e in projection["edges"] if {e["src"], e["dst"]} == pair]
    assert len(ties) == 1, projection["edges"]
    return ties[0]["weight"]


def _weight_from_the_list(contact_graph: dict, handles: tuple[str, str]) -> float:
    """The weight a reader works out from the contact graph alone: 1/(n - 1) for each conversation
    they can list that holds both handles, n being the participants it lists."""
    return round(sum(1 / (len(c["participants"]) - 1)
                     for c in contact_graph["conversations"]
                     if set(handles) <= set(c["participants"])), 6)


@pytest.mark.parametrize("mode", MODES)
def test_a_weight_divides_by_the_roster_the_reader_can_list(owner, client, mode):
    w = g.World(owner, withheld=mode)
    a1, a2 = w.node("g42 roster a1"), w.node("g42 roster a2")
    # The register's room, two AMBER identities and one RED one ...
    _room(owner, w, [("a1", a1), ("a2", a2), ("red", w.node("g42 roster red", "RED"))])
    # ... and a second room the pair share, with an unresolved member and two more RED ones.
    _room(owner, w, [("a1", a1), ("a2", a2), ("lurker", None),
                     ("red2", w.node("g42 roster red 2", "RED")),
                     ("red3", w.node("g42 roster red 3", "RED"))])

    listed = _read(client, w, w.analyst, "/comms/contact-graph")
    # Every participant of both rooms, the three the analyst cannot resolve among them.
    assert sorted(len(c["participants"]) for c in listed["conversations"]) == [3, 5]
    projected = _read(client, w, w.analyst, "/comms/co-participation")
    assert {n["key"] for n in projected["nodes"]} == {f"node:{a1}", f"node:{a2}"}
    # 1/(3 - 1) + 1/(5 - 1), from the list; by the members the analyst can resolve it would be 2.0.
    assert _weight(projected, a1, a2) == _weight_from_the_list(listed, ("a1", "a2")) == 0.75


def test_a_weight_is_one_figure_for_every_reader_of_the_room(owner, client):
    w = g.World(owner, withheld="NONE")
    a1, a2 = w.node("g42 roster a1"), w.node("g42 roster a2")
    red = w.node("g42 roster red", "RED")
    _room(owner, w, [("a1", a1), ("a2", a2), ("red", red)])
    # An AMBER member of the case under an emergency grant to RED on this case alone.
    s.break_glass(owner, w.reader, "RED", w.case_id)

    views = {who: _read(client, w, uid, "/comms/co-participation")
             for who, uid in (("AMBER", w.analyst), ("RED", w.boss),
                              ("break-glass", w.reader))}
    assert {who: _weight(v, a1, a2) for who, v in views.items()} == {
        "AMBER": 0.5, "RED": 0.5, "break-glass": 0.5}
    # The readers cleared for the third identity see it, and the tie between the other two weighs
    # what it weighs for the reader who cannot.
    keys = {who: {n["key"] for n in v["nodes"]} for who, v in views.items()}
    assert f"node:{red}" not in keys["AMBER"]
    assert f"node:{red}" in keys["RED"] and f"node:{red}" in keys["break-glass"]


def test_a_weight_never_depends_on_how_many_participants_resolve_above_the_reader(
        owner, client):
    w = g.World(owner, withheld="NONE")
    pairs = {}
    for third, identity in (("unresolved", None),
                            ("amber", w.node("g42 roster third amber")),
                            ("red", w.node("g42 roster third red", "RED"))):
        a, b = w.node(f"g42 roster {third} a"), w.node(f"g42 roster {third} b")
        _room(owner, w, [(f"{third}-a", a), (f"{third}-b", b), (f"{third}-c", identity)])
        pairs[third] = (a, b)

    projected = _read(client, w, w.analyst, "/comms/co-participation")
    assert {third: _weight(projected, a, b) for third, (a, b) in pairs.items()} == {
        "unresolved": 0.5, "amber": 0.5, "red": 0.5}


def test_an_oversized_room_is_sized_by_the_roster_the_reader_can_list(owner, client):
    w = g.World(owner, withheld="NONE")
    members = [("a1", w.node("g42 roster a1")), ("a2", w.node("g42 roster a2"))]
    members += [(f"red{n}", w.node(f"g42 roster red {n}", "RED")) for n in range(3)]
    conv = _room(owner, w, members)

    listed = _read(client, w, w.analyst, "/comms/contact-graph")
    projected = _read(client, w, w.analyst, "/comms/co-participation", max_room_size=4)
    # Two members the analyst can resolve would fit under a cap of four; the room has five.
    assert projected["edges"] == []
    [room] = projected["coverage"]["oversized"]
    [conversation] = listed["conversations"]
    assert room["conversation_id"] == conversation["conversation_id"] == conv
    assert room["participants"] == len(conversation["participants"]) == 5


# --- a handle resolved above the reader is, to the reader, an unresolved handle ------------------
#
# What the roster does not say is which identity a handle resolves to, and that is what a reader
# above whom it resolves must not learn. It is told nothing under NONE, whether under PRESENCE and how
# many under COUNT (`coverage.withheld`). Dropping such a participant while an unresolved one is drawn
# with `include_unresolved` (or counted as unresolved without it) let a reader holding the handle
# list find, under NONE, the handle that is neither an entity nor an unresolved handle.

def _the_toggle_room(owner, w, hidden: bool) -> dict:
    """Two AMBER identities and the handle `h`, resolved to a RED identity or to nothing."""
    a1, a2 = w.node("g42 toggle a1"), w.node("g42 toggle a2")
    third = w.node("g42 toggle red", "RED") if hidden else None
    conv = _room(owner, w, [("a1", a1), ("a2", a2), ("h", third)])
    return {str(w.case_id): "the case", str(a1): "a1", str(a2): "a2", conv: "the room"}


def _as_seen(answer: dict, names: dict) -> dict:
    """An answer with one case's ids written as names, its vertices and ties in one order, so the
    answers about two cases compare equal exactly when a reader could not tell them apart."""
    text = json.dumps(answer)
    for value, name in names.items():
        text = text.replace(value, name)
    seen = json.loads(text)
    for conversation in seen.get("conversations", []):
        # Ordered by message count, and these have none: the order among them is the planner's.
        conversation["participants"].sort()
    if "nodes" in seen:
        seen["nodes"].sort(key=lambda n: n["key"])
        for e in seen["edges"]:
            e["src"], e["dst"] = sorted((e["src"], e["dst"]))
        seen["edges"].sort(key=lambda e: (e["src"], e["dst"]))
    return seen


def test_a_handle_resolved_above_the_reader_draws_as_an_unresolved_handle(owner, client):
    w = g.World(owner, withheld="NONE")
    a1 = w.node("g42 draw a1")
    red = w.node("g42 draw red", "RED")
    _room(owner, w, [("a1", a1), ("hidden", red), ("lurker", None)])

    seen = _read(client, w, w.analyst, "/comms/co-participation", include_unresolved=True)
    handles = {n["label"]: n for n in seen["nodes"] if n["kind"] == "HANDLE"}
    assert set(handles) == {"hidden", "lurker"}
    hidden, lurker = handles["hidden"], handles["lurker"]
    assert (hidden["key"], lurker["key"]) == ("handle:hidden", "handle:lurker")
    assert {k: v for k, v in hidden.items() if k not in ("key", "label")} == {
        k: v for k, v in lurker.items() if k not in ("key", "label")}
    assert hidden["node_id"] is None and "not resolved to an identity" in hidden["note"]
    assert str(red) not in json.dumps(seen)
    # Each handle ties to the entity as the unresolved one does, over the room's three.
    weights = {frozenset((e["src"], e["dst"])): e["weight"] for e in seen["edges"]}
    assert weights[frozenset((f"node:{a1}", "handle:hidden"))] == weights[
        frozenset((f"node:{a1}", "handle:lurker"))] == 0.5
    # The cleared owner sees the identity, as before.
    boss = _read(client, w, w.boss, "/comms/co-participation", include_unresolved=True)
    assert f"node:{red}" in {n["key"] for n in boss["nodes"]}
    assert "handle:hidden" not in {n["key"] for n in boss["nodes"]}


@pytest.mark.parametrize("mode", ("NONE", "PRESENCE"))
def test_hidden_identities_are_counted_with_the_unresolved_under_none_and_presence(
        owner, client, mode):
    w = g.World(owner, withheld=mode)
    _room(owner, w, [("a1", w.node("g42 fold a1")), ("a2", w.node("g42 fold a2")),
                     ("hidden", w.node("g42 fold red", "RED")), ("lurker", None)])

    cov = _read(client, w, w.analyst, "/comms/co-participation")["coverage"]
    # One unresolved handle and one resolved above the analyst: two unresolved, to the analyst.
    assert cov["participants_excluded_unresolved"] == 2
    assert "participants_excluded_not_visible" not in cov
    assert cov.get("withheld") == (
        {"incomplete": True, "mode": "PRESENCE"} if mode == "PRESENCE" else None)
    # Drawn rather than excluded, neither is counted.
    drawn = _read(client, w, w.analyst, "/comms/co-participation",
                  include_unresolved=True)["coverage"]
    assert drawn["participants_excluded_unresolved"] == 0
    assert "participants_excluded_not_visible" not in drawn


def test_the_counts_stay_separate_under_count(owner, client):
    w = g.World(owner, withheld="COUNT")
    _room(owner, w, [("a1", w.node("g42 fold a1")), ("a2", w.node("g42 fold a2")),
                     ("hidden", w.node("g42 fold red", "RED")), ("lurker", None)])

    cov = _read(client, w, w.analyst, "/comms/co-participation")["coverage"]
    assert (cov["participants_excluded_unresolved"],
            cov["participants_excluded_not_visible"]) == (1, 1)
    assert cov["withheld"] == {"incomplete": True, "mode": "COUNT", "participants": 1}
    # Drawn as a handle, the participant's identity is still withheld, and COUNT still says so.
    drawn = _read(client, w, w.analyst, "/comms/co-participation",
                  include_unresolved=True)["coverage"]
    assert (drawn["participants_excluded_unresolved"],
            drawn["participants_excluded_not_visible"]) == (0, 1)
    assert drawn["withheld"] == cov["withheld"]


def test_toggling_include_unresolved_does_not_reveal_which_handle_resolves_above_the_reader(
        owner, client):
    """Two cases, each a room of two AMBER identities and the handle `h`: in one `h` resolves to a
    RED identity, in the other to nothing. Under NONE every answer the AMBER analyst can ask for is
    the same in both, either way the switch is set; under PRESENCE only the one bit differs."""
    worlds = {}
    for hidden in (True, False):
        w = g.World(owner, withheld="NONE")
        worlds[hidden] = (w, _the_toggle_room(owner, w, hidden))

    def seen(hidden, tail, **params):
        w, names = worlds[hidden]
        return _as_seen(_read(client, w, w.analyst, tail, **params), names)

    assert seen(True, "/comms/contact-graph") == seen(False, "/comms/contact-graph")
    for include_unresolved in (False, True):
        assert (seen(True, "/comms/co-participation", include_unresolved=include_unresolved)
                == seen(False, "/comms/co-participation",
                        include_unresolved=include_unresolved)), include_unresolved

    for w, _ in worlds.values():
        w.disclose("PRESENCE")
    for include_unresolved in (False, True):
        above, unresolved = (
            seen(hidden, "/comms/co-participation", include_unresolved=include_unresolved)
            for hidden in (True, False))
        assert above["coverage"].pop("withheld") == {"incomplete": True, "mode": "PRESENCE"}
        assert unresolved["coverage"].pop("withheld") == {"incomplete": False,
                                                          "mode": "PRESENCE"}
        assert above == unresolved, include_unresolved


def test_the_roster_of_a_readable_conversation_is_readable_whole(owner):
    """The premise of decision 232. If a participant row ever carries labels of its own, or its
    policy stops being its conversation's, the roster is no longer what every reader of the
    conversation can list, and how a weight divides has to be decided again."""
    from noctornal_api.rls_registry import LABEL_COLUMNS, POLICY

    columns = {r[0] for r in owner.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'comms' AND table_name = 'participant'")}
    assert {"conversation_id", "observed_handle", "identity_node_id"} <= columns
    assert columns.isdisjoint(LABEL_COLUMNS), columns & set(LABEL_COLUMNS)

    assert POLICY["comms.participant"] == "CHILD"
    policies = owner.execute(
        "SELECT polname, pg_get_expr(polqual, polrelid) FROM pg_policy "
        "WHERE polrelid = 'comms.participant'::regclass").fetchall()
    assert [name for name, _ in policies] == ["rls_gate"]
    qual = policies[0][1]
    assert "comms.conversation" in qual and "conversation_id" in qual, qual
    for label_term in ("classification", "compartments", "rls_"):
        assert label_term not in qual, qual
