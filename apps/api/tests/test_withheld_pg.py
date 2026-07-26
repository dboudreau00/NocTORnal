"""U2 -- "why is this hidden": telling an analyst their picture is
incomplete, without telling them what is in it.

The failure this closes is analytical, not cosmetic. An analyst who cannot
tell a sparse network from a censored one reads structure off a picture they
believe is complete, and a broker who looks peripheral because the two ties
that make them central are RED is a wrong answer delivered confidently.

The tests that matter are the ones asserting what is NOT disclosed:
never the classification, never the compartment, and never the location.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; withheld disclosure is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'wthh-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'wthh-%@noctornal.test'")
    c.close()


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"wthh-{uuid4().hex[:8]}@noctornal.test", "Analyst", "x" * 20)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-WTHH-{uuid4().hex[:6]}", title="Withheld",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification="GREEN")


def _node(conn, case_id, actor, label, classification="GREEN", compartments=()):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification, compartments=list(compartments),
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor))


def _edge(conn, case_id, actor, src, dst, classification="GREEN"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=src,
        dst_node_id=dst, created_by=actor, classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 rationale="vouched"))


def _svc(conn, clearance="GREEN", compartments=()):
    from noctornal_api.projections import GraphService
    return GraphService(conn, clearance=clearance,
                        compartments=frozenset(compartments))


def _projection(case_id):
    from noctornal_api.projections import Projection
    return Projection(case_id=case_id, preset="all", include_inferred=False,
                      min_confidence="LOW", as_of=None)


# --- the counts ---------------------------------------------------------

def test_a_fully_cleared_reader_is_told_nothing_is_missing(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    a = _node(conn, case_id, owner, "alpha")
    b = _node(conn, case_id, owner, "bravo")
    _edge(conn, case_id, owner, a, b)

    w = _svc(conn, "RED").withheld(_projection(case_id))
    assert w.any_withheld is False
    assert w.as_response() == {"incomplete": False, "mode": "PRESENCE"}


def test_an_under_cleared_reader_is_told_the_picture_is_incomplete(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    a = _node(conn, case_id, owner, "alpha")
    b = _node(conn, case_id, owner, "bravo")
    _node(conn, case_id, owner, "the-red-one", classification="RED")
    _edge(conn, case_id, owner, a, b)

    w = _svc(conn, "GREEN").withheld(_projection(case_id))
    assert w.any_withheld is True
    assert w.nodes == 1


def test_a_tie_hidden_only_by_its_ENDPOINT_still_counts(conn):
    """The commoner case, and the one a naive implementation misses: an edge
    is only ever returned when BOTH ends are visible, so most missing ties
    are missing because of a node, not because of their own labels."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    a = _node(conn, case_id, owner, "alpha")
    hidden = _node(conn, case_id, owner, "hidden", classification="RED")
    _edge(conn, case_id, owner, a, hidden, classification="GREEN")

    w = _svc(conn, "GREEN").withheld(_projection(case_id))
    assert w.nodes == 1
    assert w.edges == 1, "the tie is GREEN but one of its ends is not"


def test_a_compartment_you_are_not_read_into_counts_as_withheld(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    _node(conn, case_id, owner, "compartmented", compartments=("OPERATION-X",))

    assert _svc(conn, "RED").withheld(_projection(case_id)).nodes == 1
    assert _svc(conn, "RED", ("OPERATION-X",)).withheld(
        _projection(case_id)).nodes == 0


def test_the_count_applies_the_projections_OTHER_filters(conn):
    """"1,990 elements withheld" when 1,988 were excluded by the preset is
    not information, it is alarm. Only clearance counts here."""
    from noctornal_api.projections import Projection

    owner = _user(conn)
    case_id = _case(conn, owner)
    a = _node(conn, case_id, owner, "alpha")
    b = _node(conn, case_id, owner, "bravo", classification="RED")
    _edge(conn, case_id, owner, a, b)

    # A preset that excludes VOUCHED_FOR entirely: the tie is out of scope
    # for everyone, so it is not "withheld" from anybody.
    financial = Projection(case_id=case_id, preset="financial",
                           include_inferred=False, min_confidence="LOW",
                           as_of=None)
    w = _svc(conn, "GREEN").withheld(financial)
    assert w.nodes == 1, "the node is still hidden by clearance"
    assert w.edges == 0, "the tie is excluded by the preset, not by clearance"


def test_a_retracted_element_is_not_counted_as_withheld(conn):
    """It is not in anybody's projection, so it is not being kept from
    anybody. Counting it would inflate the number with elements that no
    longer exist in the live graph."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    gone = _node(conn, case_id, owner, "retracted-and-red", classification="RED")
    conn.execute(
        "UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
        "retraction_reason = 'test' WHERE node_id = %s", (owner, gone))

    assert _svc(conn, "GREEN").withheld(_projection(case_id)).nodes == 0


# --- what is NOT disclosed ----------------------------------------------

def test_presence_mode_gives_no_numbers_at_all(conn):
    """The default. It fixes the analytical error while disclosing close to
    the minimum: one bit, in a case the reader is already assigned to."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    for i in range(7):
        _node(conn, case_id, owner, f"red-{i}", classification="RED")

    body = _svc(conn, "GREEN").withheld(_projection(case_id)).as_response()
    assert body["incomplete"] is True
    assert "nodes" not in body and "edges" not in body


def test_count_mode_is_opt_in_per_case(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    _node(conn, case_id, owner, "red", classification="RED")
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 ("COUNT", case_id))

    body = _svc(conn, "GREEN").withheld(_projection(case_id)).as_response()
    assert body == {"incomplete": True, "mode": "COUNT", "nodes": 1, "edges": 0}


def test_none_mode_says_nothing_at_all_not_even_no(conn):
    """"withheld: false" would itself be an answer. The key is absent,
    exactly as it was before this existed."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    _node(conn, case_id, owner, "red", classification="RED")
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 ("NONE", case_id))

    assert _svc(conn, "GREEN").withheld(_projection(case_id)).as_response() == {}


def test_nothing_discloses_which_classification_or_compartment(conn):
    """The count is a number. Breaking it down by label would turn "you are
    missing something" into "you are missing two RED things and one in
    OPERATION-X", which is most of what the label was protecting."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "alpha")
    _node(conn, case_id, owner, "red", classification="RED")
    _node(conn, case_id, owner, "comp", compartments=("OPERATION-X",))
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 ("COUNT", case_id))

    body = _svc(conn, "GREEN").withheld(_projection(case_id)).as_response()
    serialised = repr(body)
    assert "RED" not in serialised
    assert "OPERATION-X" not in serialised
    assert set(body) <= {"incomplete", "mode", "nodes", "edges"}


def test_nothing_discloses_WHERE_the_hidden_material_is(conn):
    """Per case, never per node. "There is a hidden tie adjacent to this
    person" would localise the withheld material, which is the disclosure
    that actually matters."""
    from noctornal_api.projections import Withheld
    fields = set(Withheld.__dataclass_fields__)
    assert fields == {"mode", "any_withheld", "nodes", "edges"}, (
        "any per-node or per-edge breakdown would localise what is hidden")


def test_a_missing_case_discloses_nothing(conn):
    """Failing closed here costs an analyst a banner; failing open costs a
    disclosure."""
    from noctornal_api.projections import DISCLOSURE_NONE
    w = _svc(conn, "RED").withheld(_projection(uuid4()))
    assert w.mode == DISCLOSURE_NONE
    assert w.as_response() == {}


def test_presence_is_the_default_for_a_new_case(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    row = conn.execute('SELECT withheld_disclosure FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()
    assert row[0] == "PRESENCE"


def test_an_unknown_disclosure_mode_is_refused_by_the_database(conn):
    import psycopg
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            'UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
            ("SHOW_EVERYTHING", case_id))
