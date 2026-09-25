"""The source routes over HTTP (2026-09-24; docs/00 decision 69).

GET and POST /collection/sources, activate and deactivate, GET
/collection/runs/{id}, the run route's new fields and refusals, and the due
list's held sources. The adapter registry is replaced through the
get_adapters dependency, which is what it exists for. DATABASE_URL-gated.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0sh-"
API = "/api/v1/collection"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


class ValidatingStub(h.StubAuthorityAdapter):
    def validate_source(self, base_url, parser_config):
        return [] if base_url and "/forums/" in base_url else [
            "A board is addressed by its /forums/{id}/ URL."]


@pytest.fixture
def api(conn, monkeypatch):
    from noctornal_api.http.routers import collection as router

    client, app = h.client()
    stub = ValidatingStub()
    app.dependency_overrides[router.get_adapters] = lambda: h.adapters(stub)
    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    return client, stub


def _caller(conn, *, clearance="AMBER", roles=("COLLECTOR",), fresh=True):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email, fresh=fresh))


def _body(**over):
    body = {"kind": "XENFORO", "name": f"{P}board", "base_url":
            "https://board.example.test/forums/7/", "parser_key": "stubforum",
            "classification": "AMBER", "poll_interval_s": 900, "max_rps": 0.5}
    body.update(over)
    return body


def test_the_listing_hides_a_source_above_the_caller_and_says_what_it_may_do(conn, api):
    client, _stub = api
    _uid, amber = _caller(conn)
    red = h.source(conn, P, classification="RED")
    mine = h.source(conn, P, classification="AMBER")
    body = client.get(f"{API}/sources", headers=amber).json()
    ids = {s["id"] for s in body["sources"]}
    assert str(mine) in ids and str(red) not in ids
    assert {a["parser_key"] for a in body["adapters"]} == {"rss", "stubforum"}
    assert body["ceilings"]["XENFORO"] == "AMBER" and body["ceilings"]["TELEGRAM"] is None
    assert body["can_manage"] is True and body["can_bind"] is True
    row = next(s for s in body["sources"] if s["id"] == str(mine))
    assert row["requires_authority"] is True
    assert row["authority"]["state"] == "NONE"
    _uid, analyst = _caller(conn, roles=("ANALYST",))
    other = client.get(f"{API}/sources", headers=analyst).json()
    assert other["can_manage"] is False and other["can_bind"] is False


def test_creating_a_source_validates_labels_and_audits(conn, api):
    client, _stub = api
    uid, amber = _caller(conn)
    bad = client.post(f"{API}/sources", headers=amber,
                      json=_body(base_url="https://board.example.test/whatever"))
    assert bad.status_code == 400 and "forums/{id}" in bad.json()["detail"]
    above_me = client.post(f"{API}/sources", headers=amber,
                           json=_body(classification="RED"))
    assert above_me.status_code == 400 and "your own" in above_me.json()["detail"]
    unknown = client.post(f"{API}/sources", headers=amber,
                          json=_body(parser_key="nope"))
    assert unknown.status_code == 400
    rss_forum = client.post(f"{API}/sources", headers=amber,
                            json=_body(parser_key="rss"))
    assert rss_forum.status_code == 400
    made = client.post(f"{API}/sources", headers=amber, json=_body())
    assert made.status_code == 201, made.text
    assert "a security officer confirms it" in made.json()["next"]
    source = made.json()["source"]["id"]
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s "
                        "AND action = 'SOURCE_CREATED' AND actor_id = %s",
                        (source, uid)).fetchone()[0] == 1


def test_a_label_above_the_declared_ceiling_is_refused(conn, api, monkeypatch):
    client, _stub = api
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "GREEN")
    _uid, red = _caller(conn, clearance="RED")
    r = client.post(f"{API}/sources", headers=red, json=_body(classification="AMBER"))
    assert r.status_code == 400 and "ceiling declared" in r.json()["detail"]


def test_deactivate_and_activate_are_audited_and_404_above_the_ceiling(conn, api):
    client, _stub = api
    _uid, amber = _caller(conn)
    source = h.source(conn, P)
    red = h.source(conn, P, classification="RED")
    off = client.post(f"{API}/sources/{source}/deactivate", headers=amber,
                      json={"reason": "the board went dark"})
    assert off.status_code == 200 and off.json()["is_active"] is False
    on = client.post(f"{API}/sources/{source}/activate", headers=amber,
                     json={"reason": "it came back"})
    assert on.status_code == 200
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND "
                        "action IN ('SOURCE_DEACTIVATED', 'SOURCE_ACTIVATED')",
                        (source,)).fetchone()[0] == 2
    hidden = client.post(f"{API}/sources/{red}/deactivate", headers=amber,
                         json={"reason": "not mine to touch"})
    assert hidden.status_code == 404


def test_a_run_is_404_above_the_ceiling(conn, api):
    client, _stub = api
    _uid, amber = _caller(conn)
    red = h.source(conn, P, classification="RED", parser="rss", kind="RSS")
    run = conn.execute("INSERT INTO collect.collection_run (source_id, status) "
                       "VALUES (%s, 'OK') RETURNING id", (red,)).fetchone()[0]
    assert client.get(f"{API}/runs/{run}", headers=amber).status_code == 404
    _uid, red_hdr = _caller(conn, clearance="RED")
    detail = client.get(f"{API}/runs/{run}", headers=red_hdr)
    assert detail.status_code == 200 and detail.json()["requests"] == []


def test_the_run_route_returns_status_and_the_blocked_reason(conn, api):
    client, _stub = api
    _uid, amber = _caller(conn)
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    r = client.post(f"{API}/sources/{source}/run", headers=amber, json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "BLOCKED"
    assert "No confirmed authority covers" in body["blocked_reason"]
    assert body["notes"] == [] or isinstance(body["notes"], list)


def test_a_refused_source_is_409_and_writes_no_run(conn, api, monkeypatch):
    client, _stub = api
    monkeypatch.delenv("NOCTORNAL_FORUM_SOURCE_CEILING")
    _uid, amber = _caller(conn)
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    r = client.post(f"{API}/sources/{source}/run", headers=amber, json={})
    assert r.status_code == 409 and "not declared" in r.json()["detail"]
    assert conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (source,)).fetchone()[0] == 0


def test_the_confirmer_pressing_poll_now_is_409_with_no_run_row(conn, api):
    client, stub = api
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    both, email = h.user(conn, P, roles=("COLLECTOR", "SECURITY_OFFICER"))
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    h.authority(conn, recorder=recorder, confirmer=both, source_ids=[source],
                adapters=h.adapters(stub))
    r = client.post(f"{API}/sources/{source}/run",
                    headers=h.auth(h.session(conn, email)), json={})
    assert r.status_code == 409 and "Somebody else runs it" in r.json()["detail"]
    assert conn.execute("SELECT count(*), max(blocked_reason) FROM collect.collection_run "
                        "r JOIN collect.source s ON s.id = r.source_id "
                        "WHERE r.source_id = %s", (source,)).fetchone()[0] == 0


def test_the_due_list_carries_what_waits_on_a_person(conn, api, monkeypatch):
    client, _stub = api
    _uid, amber = _caller(conn)
    no_exit = h.source(conn, P)
    uncovered = h.source(conn, P, egress=h.egress_profile(conn, P))
    body = client.get(f"{API}/sources/due", headers=amber).json()
    refused = {s["id"]: s for s in body["refused"]}
    waiting = {s["id"]: s for s in body["awaiting_authority"]}
    assert str(no_exit) in refused and "no egress profile" in refused[str(no_exit)]["sentence"]
    assert str(uncovered) in waiting
    assert "waiting_on_persona" in body
    assert str(no_exit) not in {d["id"] for d in body["due"]}
