"""Co-participation: the bipartite projection, and what it refuses to say.

docs/10 calls the co-participation network "often the cleanest social
graph you will get". docs/03 says how to build one without lying:

    Bipartite projection to one-mode with Newman weighting (dividing by
    event size), otherwise a 500-member forum creates a spurious clique.

`analytics._mode_warning` records this as the open item it is closing.

The tests that carry this file are the ones about NOT drawing a tie: a
500-member room, an incidental third party, an unresolved handle, and a
conversation the caller may not see. Each is a way to manufacture a
relationship that does not exist.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="DATABASE_URL not set; co-participation tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cop-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.message WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cop-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"cop-{uuid4().hex[:8]}@noctornal.test", "Cop", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-COP-{uuid4().hex[:6]}", title="Cop",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _identity(conn, case_id, actor, label, classification="AMBER"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor))


def _room(conn, case_id, members, *, classification="AMBER",
          provenance="OPEN_GROUP", platform="MATRIX"):
    """A conversation whose participants are (handle, identity, incidental)."""
    from noctornal_api.comms import CommsService
    svc = CommsService(conn)
    conv = svc.open_conversation(
        case_id=case_id, platform_key=platform, provenance_class=provenance,
        external_ref=f"room-{uuid4().hex[:10]}", is_group=True,
        classification=classification)
    for handle, identity, incidental in members:
        conn.execute(
            """INSERT INTO comms.participant
                   (conversation_id, observed_handle, identity_node_id,
                    is_incidental, message_count)
               VALUES (%s, %s, %s, %s, 1)""",
            (conv, handle, identity, incidental))
    return conv


def _svc(conn, clearance="RED", compartments=frozenset()):
    from noctornal_api.coparticipation import CoParticipationService
    return CoParticipationService(conn, clearance=clearance,
                                  compartments=compartments)


def _params(case_id, **kw):
    from noctornal_api.coparticipation import CoParticipationParams
    return CoParticipationParams(case_id=case_id, **kw)


# ---------------------------------------------------------------------------
# The projection itself
# ---------------------------------------------------------------------------

def test_two_people_in_one_room_get_a_tie(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alice"),
            _identity(conn, case_id, uid, "bob"))
    _room(conn, case_id, [("alice", a, False), ("bob", b, False)])

    out = _svc(conn).project(_params(case_id))
    assert len(out["nodes"]) == 2
    assert len(out["edges"]) == 1
    assert out["edges"][0]["weight"] == 1.0        # 1/(2-1)
    assert out["edges"][0]["shared_conversations"] == 1


def test_the_derived_tie_is_marked_inferred(conn):
    """Invariant 4. Two people in a channel have not been observed
    talking to each other, and that distinction has to survive."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alice"),
            _identity(conn, case_id, uid, "bob"))
    _room(conn, case_id, [("alice", a, False), ("bob", b, False)])
    edge = _svc(conn).project(_params(case_id))["edges"][0]
    assert edge["is_inferred"] is True
    assert edge["inference_method"].startswith("co_participation/")


def test_nothing_is_written_to_the_graph(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alice"),
            _identity(conn, case_id, uid, "bob"))
    _room(conn, case_id, [("alice", a, False), ("bob", b, False)])
    before = conn.execute("SELECT count(*) FROM core.edge WHERE case_id = %s",
                          (case_id,)).fetchone()[0]
    _svc(conn).project(_params(case_id))
    assert conn.execute("SELECT count(*) FROM core.edge WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == before


# ---------------------------------------------------------------------------
# Newman weighting -- docs/03's spurious clique
# ---------------------------------------------------------------------------

def test_a_big_room_contributes_less_per_pair_than_a_dm(conn):
    """The whole point of Newman weighting. Without it, being in one
    40-person channel together is worth as much as a private
    conversation."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    people = [_identity(conn, case_id, uid, f"p{n}") for n in range(10)]
    # A ten-person room ...
    _room(conn, case_id, [(f"p{n}", people[n], False) for n in range(10)])
    # ... and a DM between two others.
    x, y = (_identity(conn, case_id, uid, "x"),
            _identity(conn, case_id, uid, "y"))
    _room(conn, case_id, [("x", x, False), ("y", y, False)])

    out = _svc(conn).project(_params(case_id))
    weights = sorted({e["weight"] for e in out["edges"]})
    assert len(weights) == 2
    assert weights[1] == 1.0                              # the DM
    assert weights[0] == pytest.approx(1 / 9, rel=1e-6)   # the ten-person room


def test_count_weighting_is_available_and_says_it_differs(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    people = [_identity(conn, case_id, uid, f"q{n}") for n in range(4)]
    _room(conn, case_id, [(f"q{n}", people[n], False) for n in range(4)])
    from noctornal_api.coparticipation import WEIGHT_COUNT
    out = _svc(conn).project(_params(case_id, weighting=WEIGHT_COUNT))
    assert {e["weight"] for e in out["edges"]} == {1.0}
    assert "NOT comparable" in out["projection"]["note"]


def test_repeated_co_participation_accumulates(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alice"),
            _identity(conn, case_id, uid, "bob"))
    for _ in range(3):
        _room(conn, case_id, [("alice", a, False), ("bob", b, False)])
    edge = _svc(conn).project(_params(case_id))["edges"][0]
    assert edge["shared_conversations"] == 3
    assert edge["weight"] == 3.0


def test_min_shared_drops_one_off_pairings(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b, c = (_identity(conn, case_id, uid, "a"),
               _identity(conn, case_id, uid, "b"),
               _identity(conn, case_id, uid, "c"))
    _room(conn, case_id, [("a", a, False), ("b", b, False)])
    _room(conn, case_id, [("a", a, False), ("b", b, False)])
    _room(conn, case_id, [("a", a, False), ("c", c, False)])
    out = _svc(conn).project(_params(case_id, min_shared=2))
    assert len(out["edges"]) == 1
    assert out["edges"][0]["shared_conversations"] == 2


# ---------------------------------------------------------------------------
# What it refuses to draw
# ---------------------------------------------------------------------------

def test_an_oversized_room_is_excluded_and_the_exclusion_is_reported(conn):
    """A cap that silently drops data is worse than no cap, because the
    output looks complete."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    people = [_identity(conn, case_id, uid, f"m{n}") for n in range(12)]
    _room(conn, case_id, [(f"m{n}", people[n], False) for n in range(12)])

    out = _svc(conn).project(_params(case_id, max_room_size=10))
    assert out["edges"] == []
    assert out["coverage"]["conversations_oversized"] == 1
    assert out["coverage"]["oversized"][0]["participants"] == 12
    # And it is not merely a count -- the room is nameable.
    assert out["coverage"]["oversized"][0]["conversation_id"]


def test_an_incidental_third_party_gets_no_ties(conn):
    """docs/08 and docs/16 L4: a third party in a group channel is not a
    subject. Drawing ties between uninvolved people because they shared a
    room is the harm is_incidental exists to prevent."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b, bystander = (_identity(conn, case_id, uid, "a"),
                       _identity(conn, case_id, uid, "b"),
                       _identity(conn, case_id, uid, "bystander"))
    _room(conn, case_id, [("a", a, False), ("b", b, False),
                          ("bystander", bystander, True)])

    out = _svc(conn).project(_params(case_id))
    assert {n["label"] for n in out["nodes"]} == {"a", "b"}
    assert out["coverage"]["participants_excluded_incidental"] == 1

    opted_in = _svc(conn).project(_params(case_id, include_incidental=True))
    assert "bystander" in {n["label"] for n in opted_in["nodes"]}


def test_unresolved_handles_are_not_promoted_to_actors(conn):
    """comms.participant deliberately does not resolve most group members
    to identities, because that manufactures actors out of a member list.
    Promoting them here would manufacture them one step later."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a = _identity(conn, case_id, uid, "alice")
    _room(conn, case_id, [("alice", a, False), ("some_lurker", None, False)])

    out = _svc(conn).project(_params(case_id))
    assert out["edges"] == []
    assert out["coverage"]["participants_excluded_unresolved"] == 1

    opted_in = _svc(conn).project(_params(case_id, include_unresolved=True))
    assert len(opted_in["edges"]) == 1
    lurker = [n for n in opted_in["nodes"] if n["kind"] == "HANDLE"][0]
    assert "not resolved to an identity" in lurker["note"]


def test_a_conversation_above_the_callers_clearance_yields_no_ties(conn):
    """A conversation can be classified above its case, so an edge derived
    from one the caller cannot see would disclose it."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "a"),
            _identity(conn, case_id, uid, "b"))
    _room(conn, case_id, [("a", a, False), ("b", b, False)],
          classification="RED")

    assert _svc(conn, clearance="AMBER").project(_params(case_id))["edges"] == []
    assert len(_svc(conn, clearance="RED").project(_params(case_id))["edges"]) == 1


def test_an_identity_above_the_callers_clearance_is_not_a_vertex(conn):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a = _identity(conn, case_id, uid, "visible")
    secret = _identity(conn, case_id, uid, "secret", classification="RED")
    _room(conn, case_id, [("visible", a, False), ("secret", secret, False)])

    out = _svc(conn, clearance="AMBER").project(_params(case_id))
    assert out["edges"] == []
    assert "secret" not in {n["label"] for n in out["nodes"]}
    assert out["coverage"]["participants_excluded_not_visible"] == 1


def test_one_person_under_two_handles_is_not_tied_to_themselves(conn):
    """A self-loop is not a tie, and one identity reached by two handles
    in one room is one participant."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a = _identity(conn, case_id, uid, "alice")
    _room(conn, case_id, [("alice", a, False), ("alice_alt", a, False)])
    out = _svc(conn).project(_params(case_id))
    assert out["edges"] == []
    assert out["coverage"]["conversations_too_small"] == 1


# ---------------------------------------------------------------------------
# Filters and reporting
# ---------------------------------------------------------------------------

def test_provenance_can_be_restricted(conn):
    """PERSONA_PARTY and OPEN_GROUP are legally distinct from the rest
    (docs/16 L4), so an analyst may need a picture built from one only."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "a"),
            _identity(conn, case_id, uid, "b"))
    _room(conn, case_id, [("a", a, False), ("b", b, False)],
          provenance="OPEN_GROUP")

    assert len(_svc(conn).project(
        _params(case_id, provenance_classes=("OPEN_GROUP",)))["edges"]) == 1
    assert _svc(conn).project(
        _params(case_id, provenance_classes=("SEIZED_DEVICE",)))["edges"] == []


def test_the_result_carries_its_own_parameters(conn):
    """docs/03: "Show the projection parameters next to the results,
    always." Every parameter changes every weight."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    out = _svc(conn).project(_params(case_id, max_room_size=25, min_shared=2))
    assert out["projection"]["max_room_size"] == 25
    assert out["projection"]["min_shared"] == 2
    assert out["projection"]["weighting"] == "NEWMAN"
    assert out["projection"]["case_id"] == str(case_id)


def test_isolates_are_not_returned_as_nodes(conn):
    """An isolate here is an artefact of the filters, and it would sit in
    the denominator of every density and percentile."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a = _identity(conn, case_id, uid, "lonely")
    _room(conn, case_id, [("lonely", a, False), ("lurker", None, False)])
    out = _svc(conn).project(_params(case_id))
    assert out["nodes"] == []


@pytest.mark.parametrize("kwargs", [
    {"weighting": "MAGIC"},
    {"min_shared": 0},
    {"max_room_size": 1},
])
def test_nonsense_parameters_are_refused(conn, kwargs):
    from noctornal_api.coparticipation import CoParticipationError
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(CoParticipationError):
        _svc(conn).project(_params(case_id, **kwargs))


# ---------------------------------------------------------------------------
# The denominator is a property of the ROOM, not of our coverage of it
# ---------------------------------------------------------------------------

def test_a_big_room_full_of_unresolved_handles_does_not_score_like_a_dm(conn):
    """THE regression for this module.

    Newman weighting divided by the count remaining AFTER incidental,
    unresolved and invisible participants were dropped. With the shipped
    defaults that is the catastrophic case, not an edge case: a
    500-member channel where only two members are resolved gave a
    denominator of 2, so 1/(2-1) = 1.0 and two people who merely sat in
    the same open channel scored EXACTLY as high as a two-party DM.

    Every earlier test in this file had all participants resolved, so
    raw_size == size and they passed either way. That is why the defect
    survived them.
    """
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alpha"),
            _identity(conn, case_id, uid, "bravo"))
    members = [("alpha", a, False), ("bravo", b, False)]
    members += [(f"lurker{n}", None, False) for n in range(38)]
    _room(conn, case_id, members)          # 40 in the room, 2 resolved

    out = _svc(conn).project(_params(case_id, max_room_size=50))
    assert len(out["edges"]) == 1
    # 1/(40-1), not 1/(2-1).
    assert out["edges"][0]["weight"] == round(1 / 39, 6)
    assert out["coverage"]["participants_excluded_unresolved"] == 38


def test_the_oversize_cap_counts_the_room_not_the_survivors(conn):
    """Same root cause, second symptom: a 500-member room with two
    resolved members escaped the cap entirely and never appeared in
    `oversized`, so the "no silent caps" guarantee reported nothing."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alpha"),
            _identity(conn, case_id, uid, "bravo"))
    members = [("alpha", a, False), ("bravo", b, False)]
    members += [(f"lurker{n}", None, False) for n in range(60)]
    _room(conn, case_id, members)          # 62 in the room, 2 resolved

    out = _svc(conn).project(_params(case_id, max_room_size=50))
    assert out["edges"] == []
    assert out["coverage"]["conversations_oversized"] == 1
    entry = out["coverage"]["oversized"][0]
    assert entry["participants"] == 62
    # Both numbers, so "why was this dropped" is answerable.
    assert entry["projectable_participants"] == 2


def test_flagging_third_parties_incidental_does_not_promote_the_remainder(conn):
    """docs/16 L4 actively ENCOURAGES flagging uninvolved participants, so
    doing the right thing must not inflate the ties between whoever is
    left."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    a, b = (_identity(conn, case_id, uid, "alpha"),
            _identity(conn, case_id, uid, "bravo"))
    bystanders = [_identity(conn, case_id, uid, f"by{n}") for n in range(18)]
    members = [("alpha", a, False), ("bravo", b, False)]
    members += [(f"by{n}", bystanders[n], True) for n in range(18)]
    _room(conn, case_id, members)          # 20 in the room, 18 incidental

    out = _svc(conn).project(_params(case_id))
    assert len(out["edges"]) == 1
    assert out["edges"][0]["weight"] == round(1 / 19, 6)
