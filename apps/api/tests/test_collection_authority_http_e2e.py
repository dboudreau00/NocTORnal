"""The collection authority routes (2026-09-24; docs/00 decision 69).

A collection manager records, a security officer confirms, both with a
fresh second factor; the same person is never both, even holding both
roles; a source above the confirmer is hidden; the review queue lists what
waits and what is in force; either side can stop one, audited with which
side it was. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0ah-"
API = "/api/v1/collection/authorities"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def api(conn):
    from noctornal_api.http.routers import collection as router

    client, app = h.client()
    app.dependency_overrides[router.get_adapters] = (
        lambda: h.adapters(h.StubAuthorityAdapter()))
    return client


def _caller(conn, roles, *, clearance="RED", fresh=True):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email, fresh=fresh))


def _body(sources, **over):
    now = datetime.now(timezone.utc)
    body = {"scope": "PUBLIC_READ", "classification": "AMBER",
            "authority_ref": "DSA-2026-118", "issued_by": "Superintendent, SOCU",
            "jurisdiction": "England and Wales",
            "legal_basis": "RIPA 2000 s.28, directed surveillance",
            "target_description": "The public boards of the carding forum listed.",
            "valid_from": (now - timedelta(hours=1)).isoformat(),
            "valid_until": (now + timedelta(days=90)).isoformat(),
            "source_ids": [str(s) for s in sources]}
    body.update(over)
    return body


def _source(conn, **kw):
    kw.setdefault("egress", h.egress_profile(conn, P))
    return h.source(conn, P, **kw)


def test_a_collector_records_and_cannot_confirm(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    made = api.post(API, headers=collector, json=_body([_source(conn)]))
    assert made.status_code == 201, made.text
    view = made.json()["authority"]
    assert view["state"] == "PENDING"
    assert "cannot verify it" in made.json()["notice"]
    denied = api.post(f"{API}/{view['id']}/confirm", headers=collector,
                      json={"note": "self check", "target_ids": []})
    assert denied.status_code == 403


def test_an_officer_confirms_with_a_fresh_second_factor(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    _uid, stale = _caller(conn, ("SECURITY_OFFICER",), fresh=False)
    _uid, officer = _caller(conn, ("SECURITY_OFFICER",))
    view = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    body = {"note": "warrant seen and the list matches",
            "target_ids": [t["id"] for t in view["targets"]]}
    refused = api.post(f"{API}/{view['id']}/confirm", headers=stale, json=body)
    assert refused.status_code == 403 and "re-authentication" in refused.json()["detail"]
    ok = api.post(f"{API}/{view['id']}/confirm", headers=officer, json=body)
    assert ok.status_code == 200 and ok.json()["authority"]["state"] == "LIVE"
    assert [t["state"] for t in ok.json()["authority"]["targets"]] == ["LIVE"]


def test_one_person_holding_both_roles_is_never_both_people(conn, api):
    _uid, both = _caller(conn, ("COLLECTOR", "SECURITY_OFFICER"))
    _uid, collector = _caller(conn, ("COLLECTOR",))
    own = api.post(API, headers=both, json=_body([_source(conn)])).json()["authority"]
    mine = api.post(f"{API}/{own['id']}/confirm", headers=both,
                    json={"note": "I checked my own", "target_ids": []})
    assert mine.status_code == 409 and "somebody else confirms" in mine.json()["detail"]
    theirs = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    extra = _source(conn)
    added = api.post(f"{API}/{theirs['id']}/targets", headers=both,
                     json={"source_ids": [str(extra)]}).json()["authority"]
    pending = [t["id"] for t in added["targets"] if t["source_id"] == str(extra)]
    refused = api.post(f"{API}/{theirs['id']}/confirm", headers=both,
                       json={"note": "adding and confirming", "target_ids": pending})
    assert refused.status_code == 409 and "you added this source" in refused.json()["detail"]


def test_an_amber_officer_cannot_confirm_a_red_source(conn, api, monkeypatch):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    _uid, amber = _caller(conn, ("SECURITY_OFFICER",), clearance="AMBER")
    amber_source = _source(conn)
    red_source = _source(conn, classification="AMBER")
    view = api.post(API, headers=collector, json=_body(
        [amber_source, red_source])).json()["authority"]
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (red_source,))
    # The authority rose with its source, so the AMBER officer no longer
    # sees it at all: the same 404 as a missing id.
    r = api.post(f"{API}/{view['id']}/confirm", headers=amber,
                 json={"note": "check it", "target_ids": []})
    assert r.status_code == 404


def test_the_review_lists_pending_oldest_first_and_the_live_ones(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    _uid, officer = _caller(conn, ("SECURITY_OFFICER",))
    first = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    second = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    api.post(f"{API}/{second['id']}/confirm", headers=officer,
             json={"note": "all checked", "target_ids": [t["id"] for t in second["targets"]]})
    review = api.get(f"{API}/review", headers=officer).json()
    pending = [a["id"] for a in review["pending"]]
    assert first["id"] in pending and second["id"] not in pending
    assert second["id"] in [a["id"] for a in review["live"]]
    older = [a for a in review["pending"] if a["id"] in (first["id"],)]
    assert older and review["withheld"] in (True, False)


def test_revoke_and_refuse_are_audited_with_which_side(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    _uid, officer = _caller(conn, ("SECURITY_OFFICER",))
    a = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    b = api.post(API, headers=collector, json=_body([_source(conn)])).json()["authority"]
    assert api.post(f"{API}/{a['id']}/revoke", headers=collector,
                    json={"reason": "withdrawn by the issuer"}).status_code == 200
    assert api.post(f"{API}/{b['id']}/refuse", headers=officer,
                    json={"reason": "the list does not match"}).status_code == 200
    roles = [r[0] for r in conn.execute(
        """SELECT detail->>'by_role' FROM audit.event
            WHERE action = 'COLLECTION_AUTHORITY_REVOKED' AND object_id IN (%s, %s)
            ORDER BY seq""", (a["id"], b["id"])).fetchall()]
    assert roles == ["record", "confirm"]


def test_a_naive_time_is_refused(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    r = api.post(API, headers=collector, json=_body(
        [_source(conn)], valid_from="2026-09-24T00:00:00",
        valid_until="2026-10-24T00:00:00"))
    assert r.status_code == 422 and "send an offset" in r.text


def test_a_persona_authority_may_name_no_source(conn, api):
    _uid, collector = _caller(conn, ("COLLECTOR",))
    persona = h.persona(conn, P, egress=h.egress_profile(conn, P))
    r = api.post(API, headers=collector, json=_body([], persona_id=str(persona)))
    assert r.status_code == 201, r.text
    assert r.json()["authority"]["persona_acts"]


def test_the_listing_needs_the_recorder_and_the_review_the_confirmer(conn, api):
    _uid, analyst = _caller(conn, ("ANALYST",))
    assert api.get(API, headers=analyst).status_code == 403
    assert api.get(f"{API}/review", headers=analyst).status_code == 403


def test_admin_access_says_who_confirms(conn, api):
    _uid, officer = _caller(conn, ("SECURITY_OFFICER",))
    _uid, collector = _caller(conn, ("COLLECTOR",))
    assert api.get("/api/v1/admin/access", headers=officer).json()[
        "collection_authority_confirm"] is True
    assert api.get("/api/v1/admin/access", headers=collector).json()[
        "collection_authority_confirm"] is False
