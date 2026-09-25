"""The sandbox over HTTP (F14, 2026-09-24).

A submit request is refused with 409 naming the reason; a record-only one
is unchanged and says it is never sent; sign-off and cancel need a fresh
second factor and answer 404 to anyone the request does not name;
awaiting-signoff lists only the caller's still-eligible rows; the policy
block never carries the token, the URL or the host; the card says whether
the sample may be sent; request, sign-off and cancel are metered.

Email prefix `sbxh-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, auth, client, make_case, make_user, token
from screening_fixtures import assert_scrubbed, declare, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

API = "/api/v1"
PREFIX = "sbxh-"
ROLE = "SBXHTEST_DETONATOR"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    declare(monkeypatch)
    c = connect()
    c.execute("""INSERT INTO iam.role (key, display_name) VALUES (%s, 'sandbox test')
                 ON CONFLICT (key) DO NOTHING""", (ROLE,))
    for permission in ("sample.detonate", "sample.read"):
        c.execute("""INSERT INTO iam.role_permission (role_key, permission_key)
                     VALUES (%s, %s) ON CONFLICT DO NOTHING""", (ROLE, permission))
    yield c
    scrub(c, PREFIX)
    c.execute("DELETE FROM iam.user_role WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role WHERE key = %s", (ROLE,))
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def cape(tmp_path, monkeypatch):
    stub, port, ca, server = capev2_stub.start(tmp_path)
    capev2_stub.configure(monkeypatch, port, ca)
    try:
        yield stub
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


def _sample(conn, store, who, **kw):
    from uuid import uuid4

    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(b"MZ" + uuid4().bytes * 8,
                                             submitted_by=who, **kw)


def _people(conn):
    who = make_user(conn, PREFIX, roles=(ROLE,))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, owner)
    return who, owner, case


def test_a_submit_request_is_refused_with_409_naming_the_reason(conn, cape, store, monkeypatch):
    http = client()
    who, owner, case = _people(conn)
    s = _sample(conn, store, who, case_id=case)
    headers = auth(token(conn, who))
    r = http.post(f"{API}/samples/{s.id}/detonation", headers=headers,
                  json={"mode": "submit", "network_route": "internet"})
    assert r.status_code == 409 and "sign-off" in r.json()["detail"]
    r = http.post(f"{API}/samples/{s.id}/detonation", headers=headers,
                  json={"mode": "submit", "network_route": "nowhere"})
    assert r.status_code == 409 and "not one this sandbox offers" in r.json()["detail"]
    monkeypatch.delenv("NOCTORNAL_SANDBOX_PROVIDER")
    monkeypatch.delenv("NOCTORNAL_SANDBOX_URL")
    r = http.post(f"{API}/samples/{s.id}/detonation", headers=headers,
                  json={"mode": "submit"})
    assert r.status_code == 409 and "no sandbox is configured" in r.json()["detail"]
    del owner


def test_a_record_only_request_is_unchanged_and_never_sent(conn, cape, store):
    http = client()
    who, _owner, _case = _people(conn)
    s = _sample(conn, store, who)
    r = http.post(f"{API}/samples/{s.id}/detonation", headers=auth(token(conn, who)),
                  json={"target": "lab box", "exposure_level": "NONE"})
    assert r.status_code == 201
    assert r.json()["submitted"] is False and "never sent" in r.json()["notice"]
    assert cape.requests == []


def test_signoff_and_cancel_need_step_up_and_answer_404_to_anyone_else(conn, cape, store):
    http = client()
    who, owner, case = _people(conn)
    s = _sample(conn, store, who, case_id=case)
    r = http.post(f"{API}/samples/{s.id}/detonation", headers=auth(token(conn, who)),
                  json={"mode": "submit", "network_route": "internet",
                        "authorised_by": str(owner), "note": "needs a live route"})
    assert r.status_code == 201, r.text
    det = r.json()["id"]
    stale = auth(token(conn, owner, fresh=False))
    assert http.post(f"{API}/samples/detonations/{det}/sign-off", headers=stale,
                     json={"approve": True}).status_code == 403
    stranger = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    assert http.post(f"{API}/samples/detonations/{det}/sign-off",
                     headers=auth(token(conn, stranger)),
                     json={"approve": True}).status_code == 404
    assert http.post(f"{API}/samples/detonations/{det}/cancel",
                     headers=auth(token(conn, stranger))).status_code == 404
    listed = http.get(f"{API}/samples/detonations/awaiting-signoff",
                      headers=auth(token(conn, owner))).json()
    assert [d["id"] for d in listed["detonations"]] == [det]
    assert listed["detonations"][0]["route_class"] == "LIVE"
    assert http.get(f"{API}/samples/detonations/awaiting-signoff",
                    headers=auth(token(conn, stranger))).json()["count"] == 0
    r = http.post(f"{API}/samples/detonations/{det}/sign-off",
                  headers=auth(token(conn, owner)), json={"approve": True})
    assert r.status_code == 200 and r.json()["status"] == "QUEUED"
    r = http.post(f"{API}/samples/detonations/{det}/cancel",
                  headers=auth(token(conn, who)))
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED"


def test_the_policy_block_never_carries_the_token_url_or_host(conn, cape, store):
    http = client()
    who, _o, _c = _people(conn)
    r = http.get(f"{API}/samples/policy", headers=auth(token(conn, who)))
    block = r.json()["sandbox"]
    assert block["configured"] is True and block["name"] == "cape"
    assert block["exposure_level"] == "NONE"
    for secret in (capev2_stub.TOKEN, "127.0.0.1", "https://"):
        assert secret not in str(block)


def test_the_card_says_whether_the_sample_may_be_sent(conn, cape, store):
    http = client()
    who, _o, _c = _people(conn)
    s = _sample(conn, store, who)
    conn.execute("UPDATE lab.sample SET classification = 'RED' WHERE id = %s", (s.id,))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (who,))
    card = http.get(f"{API}/samples/{s.id}", headers=auth(token(conn, who))).json()
    assert card["sandbox"]["configured"] is True
    assert card["sandbox"]["eligible"] is False
    assert "invariant 8" in card["sandbox"]["reason"]


def test_request_signoff_and_cancel_are_metered():
    import inspect

    from noctornal_api.http.routers import samples as routes
    from noctornal_api.ratelimit import LIMITS
    assert LIMITS["sample.detonate"].quota == 20
    for fn in (routes.request_detonation, routes.sign_off_detonation,
               routes.cancel_detonation):
        route = next(r for r in routes.router.routes if getattr(r, "endpoint", None) is fn)
        assert any("rate_limit" in repr(d.dependency) or
                   "_user_dep" in getattr(d.dependency, "__name__", "")
                   for d in route.dependencies), fn.__name__
    assert 'rate_limit("sample.detonate")' in inspect.getsource(routes)
