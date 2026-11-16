"""A conversation names its collection account only as a persona the caller can see, on the
conversation's own platform (docs/10, docs/16 L4).

`comms.conversation.collection_account_id` carries a foreign key to `collect.collection_account`.
The route checked the platform key and wrote the account id unchecked, so an id that named nothing
was the key's violation and a 500, and an id that named a persona was taken whatever the caller could
see of it. What is held here:

- an id that names nothing answers 404 and stores nothing, never a 500;
- a persona the caller may not see (its venue above their clearance, or in a compartment they do not
  hold) answers exactly as one that names nothing: the same status and body, and the same audit rows;
- a persona on another platform than the conversation's, and one placed on no platform, is refused
  with a 400 that names what is wrong, and stores nothing;
- a visible persona on the conversation's platform is recorded, a burnt one included, as it may have
  been a party before it was burnt;
- the check does not depend on the provenance class: a persona that read an open room is named the
  same way;
- the service, constructed without the caller's ceiling, refuses to check an account at all.

DATABASE_URL-gated. Rows are `cacc-`.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; comms tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "cacc-"
KEY = "CACCKEY"
NOT_FOUND = "no such persona, or it is above your clearance"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("UPDATE collect.source SET compartments = '{}' WHERE name LIKE %s",
                  (f"{P}%",))
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test'")
        c.execute("DELETE FROM iam.compartment WHERE key = %s", (KEY,))
    h.teardown(c, P)
    # A persona on a platform is never deleted by the product (burn it instead), so the guard is
    # lifted inside this transaction only.
    with c.transaction():
        c.execute("ALTER TABLE collect.collection_account DISABLE TRIGGER USER")
        c.execute("DELETE FROM collect.collection_account WHERE handle LIKE %s",
                  (f"{P}%",))
        c.execute("ALTER TABLE collect.collection_account ENABLE TRIGGER USER")
    h.teardown(c, P)
    c.execute("DELETE FROM collect.egress_profile WHERE name LIKE %s", (f"{P}%",))
    c.close()


@pytest.fixture
def client():
    return h.client()[0]


def _caller(conn, client, *, clearance="AMBER", compartments=()):
    """A case owner at `clearance` with a case of their own: (token, case id, user id)."""
    uid, email = h.user(conn, P, clearance=clearance, roles=("CASE_OWNER",))
    if compartments:
        for key in compartments:
            conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'cacc') "
                         "ON CONFLICT DO NOTHING", (key,))
        conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                     (list(compartments), uid))
    token = h.session(conn, email)
    r = client.post("/api/v1/cases", headers=h.auth(token), json={
        "code": f"OP-CACC-{uuid4().hex[:6]}", "title": "Operation Account",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return token, r.json()["id"], uid


def _venue(conn, kind="XENFORO", classification="AMBER", compartments=()):
    source = h.source(conn, P, kind=kind, classification=classification, due=False)
    if compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'cacc') "
                     "ON CONFLICT DO NOTHING", (KEY,))
        conn.execute("UPDATE collect.source SET compartments = %s WHERE id = %s",
                     (list(compartments), source))
    return source


def _persona(conn, platform, *, venue=None, status="HEALTHY"):
    """A persona on `platform`. Telegram has no venue and its own exit; a forum persona is placed
    on `venue`."""
    egress = h.egress_profile(conn, P) if platform == "TELEGRAM" else None
    return h.persona(conn, P, platform=platform, egress=egress, status=status,
                     venue=None if platform == "TELEGRAM" else venue)


def _open(client, token, case_id, *, platform, account, provenance="PERSONA_PARTY", **extra):
    body = {"platform_key": platform, "provenance_class": provenance,
            "collection_account_id": str(account), **extra}
    return client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                       headers=h.auth(token), json=body)


def _stored(conn, case_id) -> int:
    return conn.execute("SELECT count(*) FROM comms.conversation WHERE case_id = %s",
                        (case_id,)).fetchone()[0]


def _audit_rows(conn, user_id) -> int:
    return conn.execute("SELECT count(*) FROM audit.event WHERE actor_id = %s",
                        (user_id,)).fetchone()[0]


def test_an_account_id_that_names_nothing_is_not_found_and_stores_nothing(conn, client):
    token, case_id, _ = _caller(conn, client)
    r = _open(client, token, case_id, platform="TELEGRAM", account=uuid4())
    assert r.status_code == 404, r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["detail"] == NOT_FOUND
    assert _stored(conn, case_id) == 0


def test_a_hidden_account_answers_exactly_as_one_that_names_nothing(conn, client):
    """The venue is RED and the caller AMBER: the persona is as absent to them as a made-up id, in
    the status, the body and the rows the request leaves behind."""
    token, case_id, uid = _caller(conn, client, clearance="AMBER")
    hidden = _persona(conn, "XENFORO", venue=_venue(conn, classification="RED"))

    before = _audit_rows(conn, uid)
    absent = _open(client, token, case_id, platform="FORUM_PM", account=uuid4())
    after_absent = _audit_rows(conn, uid)
    above = _open(client, token, case_id, platform="FORUM_PM", account=hidden)
    after_above = _audit_rows(conn, uid)

    assert absent.status_code == above.status_code == 404
    assert absent.json() == above.json()
    assert absent.headers["content-type"] == above.headers["content-type"]
    assert after_absent - before == after_above - after_absent, (
        "a hidden account and one that names nothing leave different audit rows")
    assert _stored(conn, case_id) == 0


def test_the_account_a_caller_may_see_is_the_one_they_may_name(conn, client):
    """The same persona answers 404 to a caller below its venue and 201 to one at it: the refusal is
    the caller's ceiling, not a rule about the persona."""
    persona = _persona(conn, "XENFORO", venue=_venue(conn, classification="RED"))
    low, low_case, _ = _caller(conn, client, clearance="AMBER")
    high, high_case, _ = _caller(conn, client, clearance="RED")

    assert _open(client, low, low_case, platform="FORUM_PM",
                 account=persona).status_code == 404
    assert _open(client, high, high_case, platform="FORUM_PM",
                 account=persona).status_code == 201


def test_an_account_in_a_compartment_the_caller_lacks_answers_as_one_that_names_nothing(
        conn, client):
    persona = _persona(conn, "XENFORO", venue=_venue(conn, compartments=(KEY,)))
    token, case_id, _ = _caller(conn, client)
    keyed, keyed_case, keyed_uid = _caller(conn, client, compartments=(KEY,))
    try:
        absent = _open(client, token, case_id, platform="FORUM_PM", account=uuid4())
        hidden = _open(client, token, case_id, platform="FORUM_PM", account=persona)
        assert absent.status_code == hidden.status_code == 404
        assert absent.json() == hidden.json()
        assert _stored(conn, case_id) == 0

        assert _open(client, keyed, keyed_case, platform="FORUM_PM",
                     account=persona).status_code == 201
    finally:
        # The key is released before the fixture drops it: a compartment in use is not removable.
        conn.execute("UPDATE iam.app_user SET compartments = '{}' WHERE id = %s",
                     (keyed_uid,))


@pytest.mark.parametrize("persona_platform, conversation_platform", [
    ("TELEGRAM", "XMPP"),
    ("TELEGRAM", "DISCORD"),
    ("XENFORO", "TELEGRAM"),
    ("PHPBB", "XMPP"),
    ("DISCORD", "FORUM_PM"),
])
def test_an_account_on_another_platform_is_refused_and_stores_nothing(
        conn, client, persona_platform, conversation_platform):
    token, case_id, _ = _caller(conn, client)
    persona = _persona(conn, persona_platform, venue=_venue(conn, kind=persona_platform)
                       if persona_platform in {"XENFORO", "PHPBB"} else None)
    r = _open(client, token, case_id, platform=conversation_platform, account=persona)
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert persona_platform in detail and conversation_platform in detail
    assert _stored(conn, case_id) == 0


def test_an_account_placed_on_no_platform_is_refused(conn, client):
    """A persona with no platform cannot read anywhere (`PersonaGate` says so), so it cannot have
    been a party to anything either."""
    token, case_id, _ = _caller(conn, client)
    persona = h.persona(conn, P, platform=None, egress=h.egress_profile(conn, P),
                        venue=_venue(conn))
    r = _open(client, token, case_id, platform="TELEGRAM", account=persona)
    assert r.status_code == 400, r.text
    assert "not placed on any platform" in r.json()["detail"]
    assert _stored(conn, case_id) == 0


@pytest.mark.parametrize("persona_platform, conversation_platform", [
    ("TELEGRAM", "TELEGRAM"),
    ("DISCORD", "DISCORD"),
    ("XENFORO", "FORUM_PM"),
    ("MYBB", "FORUM_PM"),
    ("PHPBB", "FORUM_PM"),
])
def test_a_visible_account_on_the_conversations_platform_is_recorded(
        conn, client, persona_platform, conversation_platform):
    token, case_id, _ = _caller(conn, client)
    persona = _persona(conn, persona_platform, venue=_venue(conn, kind=persona_platform)
                       if persona_platform in {"XENFORO", "MYBB", "PHPBB"} else None)
    r = _open(client, token, case_id, platform=conversation_platform, account=persona,
              external_ref=f"ref-{uuid4().hex[:8]}")
    assert r.status_code == 201, r.text
    row = conn.execute(
        "SELECT collection_account_id, provenance_class FROM comms.conversation WHERE id = %s",
        (r.json()["id"],)).fetchone()
    assert row == (persona, "PERSONA_PARTY")


def test_a_burnt_account_can_still_be_named_as_a_party(conn, client):
    """A conversation is a record of what was captured, and a persona that was a party before it
    was burnt still was one."""
    token, case_id, _ = _caller(conn, client)
    persona = _persona(conn, "TELEGRAM", status="BURNED")
    assert _open(client, token, case_id, platform="TELEGRAM",
                 account=persona).status_code == 201


def test_a_persona_that_read_an_open_room_is_checked_as_a_party_is(conn, client):
    """docs/16 L4: OPEN_GROUP is the persona reading without joining. The check follows the account,
    not the provenance class."""
    token, case_id, _ = _caller(conn, client)
    persona = _persona(conn, "TELEGRAM")
    assert _open(client, token, case_id, platform="TELEGRAM", account=uuid4(),
                 provenance="OPEN_GROUP").status_code == 404
    assert _open(client, token, case_id, platform="XMPP", account=persona,
                 provenance="OPEN_GROUP").status_code == 400
    assert _open(client, token, case_id, platform="TELEGRAM", account=persona,
                 provenance="OPEN_GROUP").status_code == 201
    assert _stored(conn, case_id) == 1


def test_an_unknown_platform_is_still_answered_before_the_account(conn, client):
    """The platform key is checked first, as before, and says nothing about the account."""
    token, case_id, _ = _caller(conn, client)
    r = _open(client, token, case_id, platform="NOT_A_PLATFORM", account=uuid4())
    assert r.status_code == 400
    assert "unknown platform" in r.json()["detail"]


def test_the_service_will_not_check_an_account_without_the_callers_ceiling(conn):
    """A caller that forgot to say who is asking gets a refusal, never every persona in the
    database: the worker's reading of a persona (a NULL clearance) is not reachable from here."""
    from noctornal_api.comms import CommsError, CommsService, PERSONA_PARTY

    persona = _persona(conn, "TELEGRAM")
    uid, _ = h.user(conn, P)
    from noctornal_api.cases import CaseService
    case_id = CaseService(conn).create(
        code=f"OP-CACC-{uuid4().hex[:6]}", title="Account", legal_basis="production order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=uid, created_by=uid)
    with pytest.raises(CommsError, match="clearance"):
        CommsService(conn).open_conversation(
            case_id=case_id, platform_key="TELEGRAM", provenance_class=PERSONA_PARTY,
            collection_account_id=persona)
    assert _stored(conn, case_id) == 0


def test_a_conversation_that_names_no_account_needs_no_ceiling(conn):
    """The write paths and the seed script open conversations with no persona and no clearance."""
    from noctornal_api.cases import CaseService
    from noctornal_api.comms import CommsService, OPEN_GROUP

    uid, _ = h.user(conn, P)
    case_id = CaseService(conn).create(
        code=f"OP-CACC-{uuid4().hex[:6]}", title="Account", legal_basis="production order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=uid, created_by=uid)
    assert CommsService(conn).open_conversation(
        case_id=case_id, platform_key="MATRIX", provenance_class=OPEN_GROUP) is not None


def test_the_platform_map_has_an_entry_for_every_persona_kind_the_database_allows():
    """A persona kind the database accepts and this map lacks is refused as 'no platform a conversation can
    be recorded for' (fail closed), so adding a kind without an entry here is found by this test, not by a
    caller."""
    from noctornal_api import collection, comms
    assert set(comms.PERSONA_KIND_PLATFORM) == set(collection.PERSONA_PLATFORMS)
