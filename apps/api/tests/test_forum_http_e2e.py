"""The forum adapters over HTTP, and their readiness row (F3 and F4,
2026-09-24).

A XenForo or MyBB source is made through the product's own route (POST
/collection/sources with the forum parsers' address and settings rules,
the step-up for its exit, the audit row), polled through the run route
(refused from this server's own address; BLOCKED with no authority), and
a forum document's side rows are read back through GET
/collection/documents/{id}/forum under the labels. The default registry
is used as shipped: no override. DATABASE_URL-gated; nothing contacts a
forum (every poll here stops before a request).
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import collection_helpers as h
import forum_helpers as fh

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-g05fh-"
API = "/api/v1/collection"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def client(conn, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    return h.client()[0]


def _caller(conn, *, clearance="AMBER", roles=("COLLECTOR",), fresh=True):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email, fresh=fresh))


def _body(**over):
    body = {"kind": "XENFORO", "name": f"{P}board", "base_url": fh.XF_BOARD,
            "parser_key": "xenforo", "classification": "AMBER",
            "poll_interval_s": 900, "max_rps": 0.5,
            "parser_config": {"page_budget": 8, "recheck_pages": 1}}
    body.update(over)
    return body


def test_the_listing_offers_both_forum_parsers_and_says_how_a_read_leaves(conn, client):
    _uid, amber = _caller(conn)
    body = client.get(f"{API}/sources", headers=amber).json()
    rows = {a["parser_key"]: a for a in body["adapters"]}
    assert rows["xenforo"]["kinds"] == ["XENFORO"] and rows["mybb"]["kinds"] == ["MYBB"]
    assert rows["xenforo"]["requires_authority"] is True
    assert rows["xenforo"]["persona_platform"] is None
    assert body["forum_reads_direct"] is True


def test_a_forum_source_is_made_through_the_route_with_its_exit_and_settings(conn, client):
    uid, amber = _caller(conn)
    egress = h.egress_profile(conn, P)
    made = client.post(f"{API}/sources", headers=amber,
                       json=_body(egress_profile_id=str(egress)))
    assert made.status_code == 201, made.text
    source = made.json()["source"]["id"]
    row = conn.execute("SELECT parser_key, parser_config, egress_profile_id, kind::text "
                       "FROM collect.source WHERE id = %s", (source,)).fetchone()
    assert row == ("xenforo", {"page_budget": 8, "recheck_pages": 1}, egress, "XENFORO")
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND "
                        "action = 'SOURCE_CREATED' AND actor_id = %s",
                        (source, uid)).fetchone()[0] == 1


def test_binding_the_exit_at_creation_needs_a_recent_sign_in(conn, client):
    _uid, stale = _caller(conn, fresh=False)
    egress = h.egress_profile(conn, P)
    r = client.post(f"{API}/sources", headers=stale,
                    json=_body(egress_profile_id=str(egress)))
    assert r.status_code in (401, 403), r.text


@pytest.mark.parametrize("over, words", [
    ({"base_url": f"{fh.XF_BASE}/search/?q=dumps"}, "neither a XenForo thread nor a board"),
    ({"parser_config": {"page_budget": 50}}, "Pages per poll is a whole number from 1 to 20."),
    ({"parser_config": {"cookies": "x"}}, "does not read"),
    ({"max_rps": 2}, "at most 0.5 requests per second"),
    ({"poll_interval_s": 300}, "at most once every 900 seconds"),
    ({"kind": "MYBB", "parser_key": "mybb", "base_url": fh.MB_THREAD, "parser_config": {}},
     "time zone, date format and time format"),
    ({"kind": "MYBB", "parser_key": "mybb", "base_url": fh.MB_THREAD,
      "parser_config": {**fh.MB_CONFIG, "timezone": "Nowhere/Land"}}, "time zone is not"),
    ({"kind": "MYBB"}, "does not read MYBB sources"),
])
def test_a_forum_source_the_parser_cannot_walk_is_refused_with_a_sentence(conn, client, over, words):
    _uid, amber = _caller(conn)
    r = client.post(f"{API}/sources", headers=amber, json=_body(**over))
    assert r.status_code == 400, r.text
    assert words in r.json()["detail"]


def test_a_mybb_source_with_its_zone_and_formats_is_made(conn, client):
    _uid, amber = _caller(conn)
    r = client.post(f"{API}/sources", headers=amber, json=_body(
        kind="MYBB", parser_key="mybb", base_url=fh.MB_BOARD,
        parser_config={**fh.MB_CONFIG, "member_pages": 2}))
    assert r.status_code == 201, r.text


def test_poll_now_from_this_servers_own_address_is_refused_with_no_run(conn, client, monkeypatch):
    _uid, amber = _caller(conn)
    source = h.source(conn, P, parser="xenforo", base_url=fh.XF_THREAD,
                      egress=h.egress_profile(conn, P))
    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT")
    r = client.post(f"{API}/sources/{source}/run", headers=amber, json={})
    assert r.status_code == 409 and "own address" in r.json()["detail"]
    assert conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (source,)).fetchone()[0] == 0


def test_poll_now_with_no_authority_is_blocked_before_any_request(conn, client):
    _uid, amber = _caller(conn)
    source = h.source(conn, P, parser="xenforo", base_url=fh.XF_THREAD,
                      egress=h.egress_profile(conn, P))
    r = client.post(f"{API}/sources/{source}/run", headers=amber, json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "BLOCKED"
    assert "No confirmed authority covers" in body["blocked_reason"]
    assert conn.execute("SELECT requests FROM collect.collection_run WHERE source_id = %s",
                        (source,)).fetchone()[0] == []


def _forum_document(conn, *, classification="AMBER"):
    """A collected forum post and its side row, as a poll leaves them."""
    source = h.source(conn, P, parser="xenforo", base_url=fh.XF_THREAD,
                      classification=classification, due=False)
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, external_id, body_text,
                                         content_sha256, classification, category)
           VALUES (%s, 'post:1', 'body', %s, %s, 'FORUM_POST') RETURNING id""",
        (source, os.urandom(32), classification)).fetchone()[0]
    conn.execute("""INSERT INTO collect.forum_post (document_id, signature_text,
                        quoted_post_refs, reactions)
                    VALUES (%s, 'Jabber: sig@xmpp.example.test', ARRAY['post:9'],
                            '{"count": 2, "reactors": ["Alice"], "types": []}')""", (doc,))
    return source, doc


def test_forum_details_are_read_under_the_labels_and_404_otherwise(conn, client):
    _uid, amber = _caller(conn)
    _uid, green = _caller(conn, clearance="GREEN")
    _source, doc = _forum_document(conn)
    got = client.get(f"{API}/documents/{doc}/forum", headers=amber)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["kind"] == "post" and body["signature_text"] == "Jabber: sig@xmpp.example.test"
    assert body["quoted_post_refs"] == ["post:9"] and body["reactions"]["count"] == 2
    assert "describes the author" in body["note"]
    hidden = client.get(f"{API}/documents/{doc}/forum", headers=green)
    missing = client.get(f"{API}/documents/{uuid4()}/forum", headers=amber)
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json()["detail"] == missing.json()["detail"]


def test_forum_details_need_collection_read(conn, client):
    _uid, nobody = _caller(conn, roles=())
    _source, doc = _forum_document(conn)
    assert client.get(f"{API}/documents/{doc}/forum", headers=nobody).status_code == 403


# --- the readiness row ----------------------------------------------------------

def test_the_readiness_row_is_registered_where_it_is_settled():
    from noctornal_api import readiness

    assert "forum_collection" in readiness.CHECK_NAMES
    assert readiness.UI_TARGETS["forum_collection"] == "feeds/sources"
    assert "forum_collection" not in readiness.BLOCKING_CHECKS


def test_the_readiness_row_fails_while_the_override_is_set(conn, monkeypatch):
    from noctornal_api import readiness

    check = readiness._forum_collection(conn)
    assert not check.ok and "NOCTORNAL_FORUM_ALLOW_DIRECT is set" in check.evidence
    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT")
    assert readiness._forum_collection(conn).ok


def test_the_readiness_row_names_the_missing_retention_rules(conn, monkeypatch):
    from noctornal_api import readiness

    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT")
    # Rolled back: the deployment's own rules are never touched.
    with conn.transaction(force_rollback=True):
        conn.execute("DELETE FROM core.retention_rule "
                     "WHERE category IN ('FORUM_POST', 'FORUM_MEMBER')")
        check = readiness._forum_collection(conn)
        assert check.ok and "No retention rule covers FORUM_POST or FORUM_MEMBER" in check.caveat
        for category in ("FORUM_POST", "FORUM_MEMBER"):
            conn.execute("INSERT INTO core.retention_rule (category, retain_days, rationale) "
                         "VALUES (%s, 365, 'a test rule, rolled back')", (category,))
        assert readiness._forum_collection(conn).caveat == ""
