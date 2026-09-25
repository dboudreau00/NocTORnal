"""Personas, exits and bindings over HTTP (the collection foundation,
2026-09-24).

POST /collection/personas creates a persona with no credential on a
platform some parser reads through; GET /collection/egress-profiles is the
one exit picker; POST /collection/sources/{id}/binding says who reads a
source and through which exit, with both permissions and a fresh second
factor. DATABASE_URL-gated.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0bh-"
API = "/api/v1/collection"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


class TelegramStub(h.StubAuthorityAdapter):
    key = "stubtg"
    source_kinds = frozenset({"TELEGRAM"})
    persona_platform = "TELEGRAM"

    def validate_persona(self, fingerprint):
        return [] if fingerprint.get("device_model") else [
            "A Telegram persona records its device model."]


@pytest.fixture
def api(conn):
    from noctornal_api.http.routers import collection as router

    client, app = h.client()
    registry = h.adapters(h.StubAuthorityAdapter())
    registry["stubtg"] = TelegramStub()
    app.dependency_overrides[router.get_adapters] = lambda: registry
    return client


def _caller(conn, *, clearance="RED", roles=("COLLECTOR",), fresh=True):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email, fresh=fresh))


def _persona_body(egress, **over):
    body = {"handle": f"{P}ghost", "platform": "TELEGRAM",
            "egress_profile_id": str(egress),
            "fingerprint": {"device_model": "Pixel 7", "user_agent": "Mozilla/5.0",
                            "active_window_utc": "07:00-23:00"}}
    body.update(over)
    return body


def test_a_persona_is_created_with_no_credential_on_a_platform_a_parser_reads(conn, api):
    uid, hdr = _caller(conn)
    egress = h.egress_profile(conn, P)
    nobody = api.post(f"{API}/personas", headers=hdr,
                      json=_persona_body(egress, platform="DISCORD"))
    assert nobody.status_code == 400
    assert "No adapter in this build reads through a DISCORD persona" in nobody.json()["detail"]
    invalid = api.post(f"{API}/personas", headers=hdr,
                       json=_persona_body(egress, fingerprint={}))
    assert invalid.status_code == 400 and "device model" in invalid.json()["detail"]
    hostile = api.post(f"{API}/personas", headers=hdr, json=_persona_body(
        egress, fingerprint={"device_model": "x", "user_agent": "Mozilla\r\nX-Evil: 1"}))
    assert hostile.status_code == 400 and "printable ASCII" in hostile.json()["detail"]
    made = api.post(f"{API}/personas", headers=hdr, json=_persona_body(egress))
    assert made.status_code == 201, made.text
    assert "No credential is stored yet" in made.json()["notice"]
    persona = made.json()["persona"]
    assert persona["credential_stored"] is False
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND "
                        "action = 'PERSONA_CREATED' AND actor_id = %s",
                        (persona["id"], uid)).fetchone()[0] == 1
    taken = api.post(f"{API}/personas", headers=hdr,
                     json=_persona_body(egress, handle=f"{P}second"))
    assert taken.status_code == 400 and "one persona, one egress profile" in taken.json()["detail"]


def test_a_retired_exit_is_refused(conn, api):
    _uid, hdr = _caller(conn)
    retired = h.egress_profile(conn, P, active=False)
    assert api.post(f"{API}/personas", headers=hdr,
                    json=_persona_body(retired)).status_code == 404


def test_the_exit_listing_never_carries_a_sealed_column(conn, api):
    _uid, hdr = _caller(conn)
    h.egress_profile(conn, P)
    body = api.get(f"{API}/egress-profiles", headers=hdr).json()
    assert body["egress_profiles"]
    for row in body["egress_profiles"]:
        assert "endpoint_ciphertext" not in row and "key_id" not in row


def test_binding_needs_both_permissions_and_a_fresh_second_factor(conn, api):
    _uid, stale = _caller(conn, fresh=False)
    _uid, reader = _caller(conn, roles=("ANALYST",))
    source = h.source(conn, P)
    egress = h.egress_profile(conn, P)
    body = {"egress_profile_id": str(egress), "reason": "bind the public board"}
    refused = api.post(f"{API}/sources/{source}/binding", headers=stale, json=body)
    assert refused.status_code == 403 and "re-authentication" in refused.json()["detail"]
    assert api.post(f"{API}/sources/{source}/binding", headers=reader,
                    json=body).status_code == 403


def test_binding_refuses_what_does_not_fit_and_audits_what_does(conn, api):
    uid, hdr = _caller(conn)
    egress = h.egress_profile(conn, P)
    tg_persona = h.persona(conn, P, egress=egress)
    board = h.source(conn, P)
    wrong = api.post(f"{API}/sources/{board}/binding", headers=hdr, json={
        "collection_account_id": str(tg_persona), "reason": "a persona on a board"})
    assert wrong.status_code == 400 and "without a persona" in wrong.json()["detail"]
    chat = h.source(conn, P, kind="TELEGRAM", parser="stubtg", base_url=None)
    beside = api.post(f"{API}/sources/{chat}/binding", headers=hdr, json={
        "collection_account_id": str(tg_persona),
        "egress_profile_id": str(h.egress_profile(conn, P)),
        "reason": "both at once"})
    assert beside.status_code == 400 and "its own egress profile" in beside.json()["detail"]
    carried = api.post(f"{API}/sources/{board}/binding", headers=hdr, json={
        "egress_profile_id": str(egress), "reason": "share the persona's exit"})
    assert carried.status_code == 400 and "carries a persona" in carried.json()["detail"]
    ok = api.post(f"{API}/sources/{chat}/binding", headers=hdr, json={
        "collection_account_id": str(tg_persona), "reason": "the persona joined it",
        "reset_cursor": True})
    assert ok.status_code == 200, ok.text
    assert "needs its own confirmed authority" in ok.json()["notice"]
    row = conn.execute("SELECT collection_account_id, cursor_reset_at FROM collect.source "
                       "WHERE id = %s", (chat,)).fetchone()
    assert row[0] == tg_persona and row[1] is not None
    detail = conn.execute(
        "SELECT detail FROM audit.event WHERE object_id = %s AND "
        "action = 'SOURCE_BINDING_CHANGED'", (chat,)).fetchone()[0]
    assert detail["to_persona"] == str(tg_persona) and detail["reset_cursor"] is True


def test_binding_is_404_above_the_ceiling(conn, api):
    _uid, amber = _caller(conn, clearance="AMBER")
    red = h.source(conn, P, classification="RED")
    r = api.post(f"{API}/sources/{red}/binding", headers=amber, json={
        "egress_profile_id": str(h.egress_profile(conn, P)), "reason": "not mine"})
    assert r.status_code == 404


def test_an_rss_source_takes_no_exit(conn, api):
    _uid, hdr = _caller(conn)
    rss = h.source(conn, P, kind="RSS", parser="rss")
    r = api.post(f"{API}/sources/{rss}/binding", headers=hdr, json={
        "egress_profile_id": str(h.egress_profile(conn, P)), "reason": "try it"})
    assert r.status_code == 400 and "passive default" in r.json()["detail"]


def test_the_status_route_keeps_its_shape_and_takes_a_cooldown(conn, api):
    _uid, hdr = _caller(conn)
    pid = h.persona(conn, P, egress=h.egress_profile(conn, P))
    r = api.post(f"{API}/personas/{pid}/status", headers=hdr,
                 json={"status": "COOLDOWN", "reason": "rest a while",
                       "cooldown_hours": 6})
    assert r.status_code == 200 and r.json() == {"persona_id": str(pid),
                                                 "status": "COOLDOWN"}
