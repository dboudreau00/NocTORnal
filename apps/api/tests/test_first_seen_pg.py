"""An entity's first and last seen, derived from its live claims.

gap-first-seen (decided 2026-09-23). Nothing writes `core.node.first_seen`
or `last_seen`: `create_node` never set them and no importer does, so the
entity list's First seen column was blank on every row of every estate
(0 of 146 NIGHTJAR, 22 KESTREL and 30 CORVID entities) while the claims
under them said when each was observed. They are now derived, without a
migration, wherever an entity is read (`projections.seen_sql`): the
earliest and latest `observed_at` among the entity's LIVE claims, combined
with the stored column.

What this pins, through the three read paths the console uses (the entity
list, one entity, the projection the canvas and the inspector's fallback
read):

- the dates are the claims' observed times, earliest and latest;
- a retracted or superseded claim stops counting (the projection's rule
  for "live");
- a claim with no observed time, and a claim about one of the entity's
  ties, do not move them;
- a stored value still counts, so a writer added later is not ignored;
- the claims of every record merged into the entity count, through a chain
  of merges, until the merge is reversed, and never past the reader's
  ceiling (release review c10, 2026-09-24).

The email prefix is `fseen-` and must stay unique. Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; first seen is gated"
)

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

GRADED = {"basis": "DIRECT_OBSERVATION", "reliability": "B",
          "credibility": "2", "confidence": "MODERATE"}

T0 = datetime(2025, 1, 5, 9, 30, tzinfo=timezone.utc)
T1 = datetime(2025, 3, 1, tzinfo=timezone.utc)
T2 = datetime(2025, 8, 27, 17, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'fseen-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # The merge cases (release review c10) leave a ledger behind.
        c.execute(f"""DELETE FROM core.node_merge_edge WHERE merge_id IN
                      (SELECT id FROM core.node_merge WHERE case_id IN {csub})""")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'fseen-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _owner(conn) -> str:
    return _owner_with_id(conn)[0]


def _owner_with_id(conn):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"fseen-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Fseen", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                 (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token, uid


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-FSEEN-{uuid4().hex[:6]}", "title": "Operation Sighting",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _node(client, token, case_id, label, observed: datetime | None) -> str:
    claim = {**GRADED, **({"observed_at": observed.isoformat()} if observed else {})}
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": label,
                          "assertion": claim})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _claim(client, token, case_id, path, observed: datetime | None) -> str:
    claim = {**GRADED, **({"observed_at": observed.isoformat()} if observed else {})}
    r = client.post(f"/api/v1/cases/{case_id}/{path}/assertions",
                    headers=_auth(token), json=claim)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _seen_everywhere(client, token, case_id, node_id) -> set[tuple]:
    """(first_seen, last_seen) as each read path reports it. One answer
    expected: the three must never disagree about the same entity."""
    listed = client.get(f"/api/v1/cases/{case_id}/nodes?limit=1000",
                        headers=_auth(token))
    one = client.get(f"/api/v1/cases/{case_id}/nodes/{node_id}",
                     headers=_auth(token))
    graph = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token))
    for r in (listed, one, graph):
        assert r.status_code == 200, r.text
    rows = ([n for n in listed.json() if n["id"] == node_id]
            + [one.json()]
            + [n for n in graph.json()["nodes"] if n["id"] == node_id])
    assert len(rows) == 3, "the entity is missing from a read path"
    return {(_at(n["first_seen"]), _at(n["last_seen"])) for n in rows}


def _at(value):
    return None if value is None else datetime.fromisoformat(value)


def test_first_and_last_seen_come_from_the_entitys_claims(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "alpha", T1)
    assert _seen_everywhere(client, token, case_id, a) == {(T1, T1)}, (
        "one sighting: both ends are it")

    early = _claim(client, token, case_id, f"nodes/{a}", T0)
    _claim(client, token, case_id, f"nodes/{a}", T2)
    assert _seen_everywhere(client, token, case_id, a) == {(T0, T2)}

    # Withdrawn, it stops counting at once, as it stops holding the entity up.
    r = client.post(f"/api/v1/cases/{case_id}/assertions/{early}/retract",
                    headers=_auth(token), json={"reason": "misattributed post"})
    assert r.status_code == 204, r.text
    assert _seen_everywhere(client, token, case_id, a) == {(T1, T2)}


def test_a_claim_with_no_time_or_about_a_tie_moves_nothing(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "alpha", T1)
    b = _node(client, token, case_id, "bravo", T1)
    # A claim that does not say when leaves the window where it was.
    _claim(client, token, case_id, f"nodes/{a}", None)
    # A tie observed earlier and later than either entity is a claim about
    # the RELATIONSHIP, not a sighting of the entity.
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": a,
                          "dst_node_id": b,
                          "assertion": {**GRADED, "observed_at": T0.isoformat()}})
    assert r.status_code == 201, r.text
    _claim(client, token, case_id, f"edges/{r.json()['id']}", T2)
    assert _seen_everywhere(client, token, case_id, a) == {(T1, T1)}


def test_an_entity_whose_claims_give_no_time_reads_as_unknown(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "undated", None)
    assert _seen_everywhere(client, token, case_id, a) == {(None, None)}


def test_a_superseded_claim_stops_counting(conn, client):
    """Live is not retracted AND not superseded, the projection's rule."""
    token = _owner(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "alpha", T1)
    late = _claim(client, token, case_id, f"nodes/{a}", T2)
    replacement = _claim(client, token, case_id, f"nodes/{a}", None)
    conn.execute("UPDATE core.assertion SET superseded_at = now(), "
                 "superseded_by = %s WHERE id = %s", (replacement, late))
    assert _seen_everywhere(client, token, case_id, a) == {(T1, T1)}


def _merge(conn, case_id: str, source: str, target: str, by) -> object:
    from noctornal_api.merges import MergeService
    return MergeService(conn).merge(
        case_id=case_id, source_node_id=source, target_node_id=target,
        merged_by=by, reason="same handle, same keys: one persona")


# --- release review c10, 2026-09-24 -----------------------------------------
# A merge says the two records were always one thing, and it leaves the
# absorbed record's claims on that record, which every list and the canvas
# then hide. The survivor's window must cover them, through chains, stop at
# once when the merge is reversed, and never reach past the reader.

T_EARLY = datetime(2024, 1, 10, tzinfo=timezone.utc)
T_MID = datetime(2025, 6, 1, tzinfo=timezone.utc)
T_LATE = datetime(2026, 3, 3, tzinfo=timezone.utc)


def test_a_merged_persona_s_sightings_count_for_the_survivor(conn, client):
    token, uid = _owner_with_id(conn)
    case_id = _case(client, token)
    old = _node(client, token, case_id, "zz_old", T_EARLY)
    new = _node(client, token, case_id, "zz_new", T_MID)
    assert _seen_everywhere(client, token, case_id, new) == {(T_MID, T_MID)}

    record = _merge(conn, case_id, old, new, uid)
    assert _seen_everywhere(client, token, case_id, new) == {(T_EARLY, T_MID)}, (
        "the absorbed persona's 2024 sighting dropped out of the survivor")

    # Reversed, the redirect is gone and so is the borrowed sighting.
    from noctornal_api.merges import MergeService
    MergeService(conn).unmerge(record.id, reversed_by=uid,
                               reason="two actors after all")
    assert _seen_everywhere(client, token, case_id, new) == {(T_MID, T_MID)}
    assert _seen_everywhere(client, token, case_id, old) == {(T_EARLY, T_EARLY)}


def test_a_chain_of_merges_counts_every_hop(conn, client):
    """A record that has absorbed others can be merged onward (merges.py
    refuses only a source or target that is itself merged away), so one
    level of redirect is not enough."""
    token, uid = _owner_with_id(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "zz_a", T_EARLY)
    b = _node(client, token, case_id, "zz_b", T_MID)
    c = _node(client, token, case_id, "zz_c", T_LATE)
    _merge(conn, case_id, a, b, uid)
    _merge(conn, case_id, b, c, uid)
    assert _seen_everywhere(client, token, case_id, c) == {(T_EARLY, T_LATE)}


def test_an_absorbed_record_above_the_reader_moves_nothing(conn, client):
    """An assertion has no marking of its own, so an absorbed RED or
    compartmented record's dates would reach an AMBER reader who can see
    only the survivor. Every hop is held to the reader's ceiling."""
    token, uid = _owner_with_id(conn)
    case_id = _case(client, token)
    red = _node(client, token, case_id, "zz_red", T_EARLY)
    walled = _node(client, token, case_id, "zz_walled", datetime(2023, 5, 5, tzinfo=timezone.utc))
    beyond = _node(client, token, case_id, "zz_beyond", datetime(2022, 2, 2, tzinfo=timezone.utc))
    survivor = _node(client, token, case_id, "zz_survivor", T_MID)
    # Merged INTO the hidden record before it was merged onward: reachable
    # only through it, so the walk stops at the hidden hop and never reports
    # what lies behind it.
    _merge(conn, case_id, beyond, red, uid)
    _merge(conn, case_id, red, survivor, uid)
    _merge(conn, case_id, walled, survivor, uid)
    conn.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s", (red,))
    # Registered and left registered, as the other compartment tests do: a
    # key is shared vocabulary, not this test's data.
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", ("OP-FSEEN", "OP-FSEEN (first seen test)"))
    conn.execute("UPDATE core.node SET compartments = ARRAY['OP-FSEEN'] WHERE id = %s",
                 (walled,))
    assert _seen_everywhere(client, token, case_id, survivor) == {(T_MID, T_MID)}, (
        "a record the reader may not see moved the survivor's dates")

    # Cleared to see them, the reader gets the whole tree.
    conn.execute("UPDATE core.node SET classification = 'AMBER' WHERE id = %s", (red,))
    conn.execute("UPDATE core.node SET compartments = '{}' WHERE id = %s", (walled,))
    assert _seen_everywhere(client, token, case_id, survivor) == {
        (datetime(2022, 2, 2, tzinfo=timezone.utc), T_MID)}


def test_a_stored_value_still_counts(conn, client):
    """Nothing writes the columns today. A writer added later must not be
    silently overruled by the derivation, and must not blank it either."""
    token = _owner(conn)
    case_id = _case(client, token)
    a = _node(client, token, case_id, "alpha", T1)
    earlier = datetime(2024, 12, 24, tzinfo=timezone.utc)
    conn.execute("UPDATE core.node SET first_seen = %s WHERE id = %s",
                 (earlier, a))
    assert _seen_everywhere(client, token, case_id, a) == {(earlier, T1)}
