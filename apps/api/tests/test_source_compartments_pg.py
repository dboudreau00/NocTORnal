"""Compartments on a collection source (docs/17 F43, docs/00 decision 78's
open half, 2026-10-02; Alembic 0163).

- a source is filed under compartments its creator holds, and only those;
  an unregistered key is refused by the binding;
- every document the source collects inherits them, and the document
  readers hold them to the reader's (test_document_reads_check_compartments
  holds every reader statically; this is the live half);
- a source under a compartment the reader lacks is absent from the listing,
  the due list, the runs, a run's detail and a manual poll, and from the
  authority service's targets, and a reader who gave no compartments sees
  no compartmented source at all (fail closed);
- the route takes the compartments on creation and refuses a key the
  caller does not hold.

DATABASE_URL-gated. Account and source prefix `test-srcc-`.
"""
from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-srcc-"
API = "/api/v1/collection"
KEY = "SRCC-RED-TEAM"


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
    # A source an authority names is kept, deactivated, by the teardown;
    # its key is cleared here, or 0163's downgrade refuses the migration
    # round trip the suite runs (0070's precedent for documents).
    c.execute("UPDATE collect.source SET compartments = '{}' WHERE name LIKE %s",
              (f"{P}%",))
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _holder(conn, *, roles=("COLLECTOR",), keys=(KEY,), clearance="RED"):
    uid, email = h.user(conn, P, roles=roles, clearance=clearance)
    # Registered here as well as in the fixture: a fixture that writes a
    # compartment column registers the key in its own function (0059 refuses
    # an unregistered one on a fresh database; test_fixture_invariants).
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, "Source compartment test"))
    conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                 (list(keys), uid))
    return uid, email


def _svc(conn, stub=None):
    from noctornal_api.collection import CollectionService
    return CollectionService(conn, h.adapters(stub) if stub else None,
                             sleep=lambda _s: None)


def _create(conn, who, *, compartments=(), held=(KEY,), **over):
    kw = {"kind": "XENFORO", "name": f"{P}src-{uuid4().hex[:6]}",
          "base_url": "https://board.example.test/forums/marketplace.7/",
          "parser_key": "xenforo", "classification": "AMBER",
          "max_rps": 0.5, "poll_interval_s": 900,
          "egress_profile_id": h.egress_profile(conn, P),
          "actor_id": who, "clearance": "RED",
          "compartments": list(compartments), "held_compartments": frozenset(held)}
    kw.update(over)
    return _svc(conn).create_source(**kw)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

def test_a_source_is_filed_under_compartments_its_creator_holds(conn):
    who, _ = _holder(conn)
    made = _create(conn, who, compartments=[KEY])
    assert made["compartments"] == [KEY]
    row = conn.execute("SELECT compartments FROM collect.source WHERE id = %s",
                       (made["id"],)).fetchone()
    assert row[0] == [KEY]
    audit = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'SOURCE_CREATED' AND object_id = %s",
        (made["id"],)).fetchone()[0]
    assert audit["compartments"] == [KEY]


def test_a_creator_who_lacks_the_key_is_refused_and_an_unregistered_key_too(conn):
    from noctornal_api.collection import CollectionError

    who, _ = _holder(conn, keys=())
    with pytest.raises(CollectionError, match="do not hold"):
        _create(conn, who, compartments=[KEY], held=())
    # The binding refuses a key nobody registered, whatever the caller
    # claims to hold (a typo in a need-to-know lock is silent no-access).
    holder, _ = _holder(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="not registered"):
        with conn.transaction():
            _create(conn, holder, compartments=["SRCC-NOT-A-KEY"],
                    held=(KEY, "SRCC-NOT-A-KEY"))


# ---------------------------------------------------------------------------
# Inheritance and visibility
# ---------------------------------------------------------------------------

def _compartmented_world(conn):
    """A compartmented stub forum source under a confirmed authority, with
    two documents collected into it."""
    from noctornal_api.collection import FetchResult, Item

    recorder, _ = _holder(conn)
    confirmer, _ = _holder(conn, roles=("SECURITY_OFFICER",))
    stub = h.StubAuthorityAdapter(produce=lambda _ctx: FetchResult(
        items=[Item(external_id="post:1", url="https://board.example.test/posts/1/",
                    body="one", title="t"),
               Item(external_id="post:2", url="https://board.example.test/posts/2/",
                    body="two")], http_status=200))
    egress = h.egress_profile(conn, P)
    source = h.source(conn, P, kind="XENFORO", parser="stubforum", egress=egress)
    h.authority(conn, recorder=recorder, confirmer=confirmer, source_ids=[source],
                adapters=h.adapters(stub), clearance="RED")
    # Filed under the key after the authority (the helper's record passes
    # no compartments, and a recorder who gave none is refused the source).
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", (KEY, "Source compartment test"))
    conn.execute("UPDATE collect.source SET compartments = %s WHERE id = %s",
                 ([KEY], source))
    result = _svc(conn, stub).run_once(source, actor_id=None)
    assert result.status == "OK", result
    return {"recorder": recorder, "confirmer": confirmer, "source": source,
            "stub": stub, "run_id": result.run_id}


def test_every_document_a_compartmented_source_collects_carries_its_compartments(conn):
    w = _compartmented_world(conn)
    rows = conn.execute("SELECT compartments FROM collect.document WHERE source_id = %s",
                        (w["source"],)).fetchall()
    assert len(rows) == 2 and all(r[0] == [KEY] for r in rows)
    svc = _svc(conn)
    # The document readers hold them to the reader's own.
    assert svc.documents(clearance="RED", compartments=frozenset(), source_id=w["source"]) == []
    seen = svc.documents(clearance="RED", compartments=frozenset({KEY}),
                         source_id=w["source"])
    assert len(seen) == 2 and all(d["compartments"] == [KEY] for d in seen)


def test_a_compartmented_source_is_absent_from_every_reader_who_lacks_the_key(conn):
    from noctornal_api.collection import CollectionNotFound
    from noctornal_api.collection_authority import CollectionAuthorityService

    w = _compartmented_world(conn)
    svc = _svc(conn, w["stub"])
    sid = str(w["source"])
    with_key, without, none = frozenset({KEY}), frozenset(), None
    assert sid in {s["id"] for s in svc.sources(clearance="RED", compartments=with_key)}
    assert sid not in {s["id"] for s in svc.sources(clearance="RED", compartments=without)}
    assert sid not in {s["id"] for s in svc.sources(clearance="RED", compartments=none)}, (
        "a reader that gave no compartments sees no compartmented source")
    listed = svc.sources(clearance="RED", compartments=with_key)
    assert next(s for s in listed if s["id"] == sid)["compartments"] == [KEY]
    assert [r["id"] for r in svc.runs(source_id=w["source"], clearance="RED",
                                       compartments=with_key)]
    assert svc.runs(source_id=w["source"], clearance="RED", compartments=without) == []
    svc.run_detail(w["run_id"], clearance="RED", compartments=with_key)
    with pytest.raises(CollectionNotFound):
        svc.run_detail(w["run_id"], clearance="RED", compartments=without)
    conn.execute("UPDATE collect.source SET next_due_at = now() - interval '1 minute' "
                 "WHERE id = %s", (w["source"],))
    due = {str(d["id"]) for d in svc.due_sources(clearance="RED", compartments=with_key)}
    assert sid in due
    assert sid not in {str(d["id"]) for d in svc.due_sources(clearance="RED",
                                                              compartments=without)}
    # The worker (no ceiling) sees every source, so the cron still polls it.
    assert sid in {str(d["id"]) for d in svc.due_sources(clearance=None)}
    with pytest.raises(CollectionNotFound):
        svc.run_once(w["source"], actor_id=w["recorder"], clearance="RED",
                     compartments=without)
    # The authority service: a target under a key the caller lacks is absent.
    authority = CollectionAuthorityService(conn, h.adapters(w["stub"]))
    with pytest.raises(CollectionNotFound):
        authority._target_sources([w["source"]], persona_id=None, classification="AMBER",
                                  clearance="RED", compartments=without)
    assert authority._target_sources([w["source"]], persona_id=None,
                                     classification="AMBER", clearance="RED",
                                     compartments=with_key)
    uncovered = {x["id"] for x in authority.uncovered_sources(clearance="RED",
                                                              compartments=without)}
    assert sid not in uncovered


def test_the_routes_take_the_compartments_and_hold_the_caller_to_them(conn, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    client, _app = h.client()
    holder, email = _holder(conn)
    other, other_email = _holder(conn, keys=())
    egress = h.egress_profile(conn, P)
    body = {"kind": "XENFORO", "name": f"{P}route", "parser_key": "xenforo",
            "base_url": "https://board.example.test/forums/marketplace.7/",
            "classification": "AMBER", "poll_interval_s": 900, "max_rps": 0.5,
            "parser_config": {}, "egress_profile_id": str(egress),
            "compartments": [KEY]}
    refused = client.post(f"{API}/sources", headers=h.auth(h.session(conn, other_email)),
                          json=body)
    assert refused.status_code == 400, refused.text
    assert "do not hold" in refused.json()["detail"]
    made = client.post(f"{API}/sources", headers=h.auth(h.session(conn, email)), json=body)
    assert made.status_code == 201, made.text
    assert made.json()["source"]["compartments"] == [KEY]
    sid = made.json()["source"]["id"]
    mine = client.get(f"{API}/sources", headers=h.auth(h.session(conn, email))).json()
    assert sid in {s["id"] for s in mine["sources"]}
    theirs = client.get(f"{API}/sources", headers=h.auth(h.session(conn, other_email))).json()
    assert sid not in {s["id"] for s in theirs["sources"]}
    gone = client.get(f"{API}/runs", params={"source_id": sid},
                      headers=h.auth(h.session(conn, other_email)))
    assert gone.status_code == 200 and gone.json()["runs"] == []


def test_the_source_compartment_column_is_bound_and_known_to_the_release():
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS, NOUNS
    assert ("collect", "source", "compartments", "array") in BOUND_COLUMNS
    assert NOUNS[("collect", "source")] == ("collection source", "collection sources")
