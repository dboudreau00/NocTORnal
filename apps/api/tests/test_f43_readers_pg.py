"""F43's remaining readers and writers honour a source's compartments (g40
verify round, 2026-10-03; Alembic 0163).

The first F43 round converted the document and source readers. The verifier
found the rest: the unhealthy and never-polled lists named a compartmented
source to a reader without the key; the personas listing named the venue
source and its address; a persona bound to a compartmented source could be
locked or burnt by anyone cleared to its label; the separation check
answered for a source the reader could not see; the key holder could not
deactivate or rebind their own source; a persona-suspended notice carried no
compartments; and an authority over a compartmented source showed its free
text to a reader who saw only its targets array hidden. Each is held here at
the service and, where a route was wrong, through the route.

DATABASE_URL-gated. Account and source prefix `test-srcc-` (the cleanup of
test_source_compartments_pg).
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h
from test_source_compartments_pg import KEY, P, _create, _holder

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1/collection"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
              "ON CONFLICT (key) DO NOTHING", (KEY, "Source compartment test"))
    yield c
    c.execute("UPDATE collect.source SET compartments = '{}' WHERE name LIKE %s",
              (f"{P}%",))
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _compartmented_persona(conn, holder, *, via="venue"):
    """A forum persona tied to a compartmented source, either as the venue
    it is registered on or as the source it is bound to."""
    made = _create(conn, holder, compartments=[KEY])
    egress = h.egress_profile(conn, P)
    if via == "venue":
        persona = h.persona(conn, P, platform="XENFORO", egress=egress,
                            venue=made["id"])
    else:
        persona = h.persona(conn, P, platform="XENFORO", egress=egress)
        conn.execute("UPDATE collect.source SET collection_account_id = %s, "
                     "egress_profile_id = NULL WHERE id = %s", (persona, made["id"]))
    return made, persona


# ---------------------------------------------------------------------------
# Blocker 3: the lists and the personas listing
# ---------------------------------------------------------------------------

def test_the_unhealthy_and_never_polled_lists_hide_a_compartmented_source(conn):
    from noctornal_api.collection import CollectionService

    holder, _ = _holder(conn)
    made = _create(conn, holder, compartments=[KEY])
    svc = CollectionService(conn)
    sid = made["id"]
    # Never polled: listed for the key's holder, absent for everyone else.
    assert sid in {s["id"] for s in svc.never_polled_sources(
        clearance="RED", compartments=frozenset({KEY}))}
    for held in (frozenset(), None):
        assert sid not in {s["id"] for s in svc.never_polled_sources(
            clearance="RED", compartments=held)}
    # Failing, with a blocked reason that names what it is.
    conn.execute("UPDATE collect.source SET consecutive_failures = 3, "
                 "blocked_reason = 'the board moved', blocked_at = now() "
                 "WHERE id = %s", (sid,))
    mine = {s["id"]: s for s in svc.unhealthy_sources(
        clearance="RED", compartments=frozenset({KEY}))}
    assert mine[sid]["blocked_reason"] == "the board moved"
    for held in (frozenset(), None):
        assert sid not in {s["id"] for s in svc.unhealthy_sources(
            clearance="RED", compartments=held)}
    # The scheduler (no ceiling) still sees it.
    assert sid in {s["id"] for s in svc.unhealthy_sources(clearance=None)}


def test_the_unhealthy_route_hides_a_compartmented_source_from_a_reader_without_the_key(
        conn, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    client, _app = h.client()
    holder, holder_email = _holder(conn)
    _other, other_email = _holder(conn, keys=())
    made = _create(conn, holder, compartments=[KEY])
    url = f"{API}/sources/unhealthy"
    theirs = client.get(url, headers=h.auth(h.session(conn, other_email)))
    assert theirs.status_code == 200
    assert made["id"] not in [s["id"] for s in theirs.json()["never_polled"]]
    assert made["name"] not in theirs.text
    mine = client.get(url, headers=h.auth(h.session(conn, holder_email)))
    assert made["id"] in [s["id"] for s in mine.json()["never_polled"]]


def test_a_persona_of_a_compartmented_source_is_hidden_with_its_venue(conn):
    from noctornal_api.collection import PersonaVault

    holder, _ = _holder(conn)
    for via in ("venue", "binding"):
        made, persona = _compartmented_persona(conn, holder, via=via)
        vault = PersonaVault(conn)
        seen = {r["id"]: r for r in vault.personas(
            clearance="RED", compartments=frozenset({KEY}))}
        assert str(persona) in seen, via
        if via == "venue":
            assert seen[str(persona)]["source_name"] == made["name"]
        for held in (frozenset(), None):
            listed = vault.personas(clearance="RED", compartments=held)
            assert str(persona) not in {r["id"] for r in listed}, via
            assert made["name"] not in str(listed), via
            assert vault.visible(persona, clearance="RED", compartments=held) is False
        assert vault.visible(persona, clearance="RED",
                             compartments=frozenset({KEY})) is True


def test_a_reader_without_the_key_cannot_lock_or_burn_a_persona_of_a_compartmented_source(
        conn):
    from noctornal_api.collection import CollectionNotFound, PersonaVault

    holder, _ = _holder(conn)
    other, _ = _holder(conn, keys=())
    _made, persona = _compartmented_persona(conn, holder, via="binding")
    vault = PersonaVault(conn)
    for status in ("LOCKED", "BURNED"):
        with pytest.raises(CollectionNotFound):
            vault.set_status(persona, status, actor_id=other, reason="not mine to stop",
                             clearance="RED", compartments=frozenset())
    assert conn.execute("SELECT status FROM collect.collection_account WHERE id = %s",
                        (persona,)).fetchone()[0] == "HEALTHY"
    out = vault.set_status(persona, "LOCKED", actor_id=holder, reason="holder stops it",
                           clearance="RED", compartments=frozenset({KEY}))
    assert out["status"] == "LOCKED"


def test_the_separation_check_is_a_404_for_a_compartmented_source_without_the_key(conn):
    from uuid import UUID

    from noctornal_api.collection import CollectionNotFound, PersonaVault

    holder, _ = _holder(conn)
    made = _create(conn, holder, compartments=[KEY])
    vault = PersonaVault(conn)
    sid = UUID(made["id"])
    for held in (frozenset(), None):
        with pytest.raises(CollectionNotFound):
            vault.check_egress_separation(sid, clearance="RED", compartments=held)
    assert vault.check_egress_separation(
        sid, clearance="RED", compartments=frozenset({KEY})) == []


# ---------------------------------------------------------------------------
# Major 5: the writers of the key's own holder
# ---------------------------------------------------------------------------

def test_a_holder_stops_and_rebinds_their_own_compartmented_source_and_others_meet_a_404(
        conn, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    client, _app = h.client()
    holder, holder_email = _holder(conn)
    _other, other_email = _holder(conn, keys=())
    egress = h.egress_profile(conn, P)
    body = {"kind": "XENFORO", "name": f"{P}route2", "parser_key": "xenforo",
            "base_url": "https://board.example.test/forums/marketplace.7/",
            "classification": "AMBER", "poll_interval_s": 900, "max_rps": 0.5,
            "parser_config": {}, "egress_profile_id": str(egress),
            "compartments": [KEY]}
    hdr = h.auth(h.session(conn, holder_email))
    made = client.post(f"{API}/sources", headers=hdr, json=body)
    assert made.status_code == 201, made.text
    sid = made.json()["source"]["id"]
    why = {"reason": "stopping the collection"}
    theirs = h.auth(h.session(conn, other_email))
    assert client.post(f"{API}/sources/{sid}/deactivate", headers=theirs,
                       json=why).status_code == 404
    stopped = client.post(f"{API}/sources/{sid}/deactivate", headers=hdr, json=why)
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["is_active"] is False
    assert client.post(f"{API}/sources/{sid}/activate", headers=hdr,
                       json=why).status_code == 200
    # The rebind to another exit: the holder's, not a stranger's.
    other_exit = h.egress_profile(conn, P)
    rebind = {"egress_profile_id": str(other_exit),
              "reason": "moving it to another exit", "reset_cursor": False}
    assert client.post(f"{API}/sources/{sid}/binding", headers=theirs,
                       json=rebind).status_code == 404
    done = client.post(f"{API}/sources/{sid}/binding", headers=hdr, json=rebind)
    assert done.status_code == 200, done.text
    assert done.json()["egress_profile_id"] == str(other_exit)


def test_a_persona_suspended_notice_carries_the_compartments_of_its_sources(conn):
    from noctornal_api import notify_events

    holder, _ = _holder(conn)
    _made, persona = _compartmented_persona(conn, holder, via="binding")
    notify_events.persona_suspended(conn, persona_id=persona, reason="test refusal")
    rows = conn.execute(
        """SELECT compartments FROM notify.notification
            WHERE kind = 'PERSONA_SUSPENDED' AND object_id = %s""",
        (persona,)).fetchall()
    assert rows, "the holder manager is told"
    assert all(KEY in (r[0] or []) for r in rows)
    conn.execute("DELETE FROM notify.notification WHERE object_id = %s", (persona,))


# ---------------------------------------------------------------------------
# Major 5e: an authority over a compartmented source is withheld whole
# ---------------------------------------------------------------------------

def test_an_authority_over_a_compartmented_source_is_withheld_whole_without_the_key(conn):
    from noctornal_api.collection import CollectionNotFound
    from noctornal_api.collection_authority import CollectionAuthorityService

    recorder, _ = _holder(conn)
    confirmer, _ = _holder(conn, roles=("SECURITY_OFFICER",))
    made = _create(conn, recorder, compartments=[KEY])
    egress = h.egress_profile(conn, P)
    conn.execute("UPDATE collect.source SET egress_profile_id = %s WHERE id = %s",
                 (egress, made["id"]))
    from noctornal_api.collection import default_adapters
    svc = CollectionAuthorityService(conn, default_adapters())
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    # A marker of this run's own: authorities are never deleted, so an
    # earlier run's text may still be listed once its source lost its key.
    marker = f"red team {uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    view = svc.record(
        persona_id=None, scope="PUBLIC_READ", classification="AMBER",
        authority_ref="WARRANT-2026-0043", issued_by="Duty magistrate",
        jurisdiction="England and Wales", legal_basis="RIPA 2000 s.28",
        member_authority_ref=None,
        target_description=f"The {marker} private board named in the order.",
        valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=30),
        source_ids=[made["id"]], recorded_by=recorder, clearance="RED",
        compartments=frozenset({KEY}))
    aid = view["id"]
    assert marker in view["target_description"]
    # The holder reads it, lists it and sees it in the confirmer's queue.
    held = frozenset({KEY})
    assert aid in {a["id"] for a in svc.listing(
        clearance="RED", compartments=held)["authorities"]}
    assert aid in {a["id"] for a in svc.review(
        clearance="RED", compartments=held)["pending"]}
    # A reader without the key meets no such authority anywhere, and is told
    # only that something was withheld.
    for none in (frozenset(), None):
        listing = svc.listing(clearance="RED", compartments=none)
        assert aid not in {a["id"] for a in listing["authorities"]}
        assert (marker in str(listing)) is False
        assert listing["withheld"] is True
        assert aid not in {a["id"] for a in svc.review(
            clearance="RED", compartments=none)["pending"]}
        with pytest.raises(CollectionNotFound):
            svc.view(aid, clearance="RED", compartments=none)
        with pytest.raises(CollectionNotFound):
            svc.confirm(aid, confirmed_by=confirmer, note="not mine to confirm",
                        target_ids=[t["id"] for t in view["targets"]],
                        clearance="RED", compartments=none)
        with pytest.raises(CollectionNotFound):
            svc.revoke(aid, revoked_by=confirmer, reason="not mine to stop either",
                       by_role="confirm", clearance="RED", compartments=none)
    # The key's holder who is a second person confirms it.
    confirmed = svc.confirm(aid, confirmed_by=confirmer, note="seen the order",
                            target_ids=[t["id"] for t in view["targets"]],
                            clearance="RED", compartments=held)
    assert confirmed["state"] == "LIVE"
