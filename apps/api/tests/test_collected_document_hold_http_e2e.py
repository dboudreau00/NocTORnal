"""The document-level legal hold over HTTP (2026-09-24; docs/00
decision 74).

POST /retention/documents/{id}/legal-hold holds every version of a
collected document, needs retention.manage AND collection.read, a reason
either way, and answers a document the caller may not see with the 404 a
random id gets. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0dh-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


class _Api:
    """A test client whose rate limiter is replaced before every call: the
    hold route is metered under retention.destroy (a burst of 3), and a
    test that places and lifts is not a test of the meter."""

    def __init__(self):
        self.client, self.app = h.client()

    def post(self, *args, **kw):
        from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
        self.app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
        return self.client.post(*args, **kw)

    def get(self, *args, **kw):
        return self.client.get(*args, **kw)


@pytest.fixture
def api():
    return _Api()


def _caller(conn, roles=("CASE_OWNER",), clearance="RED"):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email))


def _doc(conn, source, external_id="post:1", *, version=1, supersedes=None,
         classification="AMBER"):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                supersedes_id, classification, retain_until)
           VALUES (%s, %s, 'b', %s, %s, %s, %s, %s) RETURNING id""",
        (source, external_id, os.urandom(32), version, supersedes, classification,
         datetime.now(timezone.utc) - timedelta(days=1))).fetchone()[0]


def _url(doc):
    return f"/api/v1/retention/documents/{doc}/legal-hold"


def test_a_hold_covers_every_version_and_is_audited_and_lifted_with_a_reason(conn, api):
    uid, hdr = _caller(conn)
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    v1 = _doc(conn, source)
    v2 = _doc(conn, source, version=2, supersedes=v1)
    short = api.post(_url(v2), headers=hdr, json={"on": True, "reason": "x"})
    assert short.status_code == 400
    placed = api.post(_url(v2), headers=hdr,
                      json={"on": True, "reason": "court order 2026-55"})
    assert placed.status_code == 200 and placed.json()["versions"] == 2
    held = conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s "
                        "AND legal_hold AND legal_hold_by = %s",
                        (source, uid)).fetchone()[0]
    assert held == 2
    no_reason = api.post(_url(v2), headers=hdr, json={"on": False})
    assert no_reason.status_code == 400
    lifted = api.post(_url(v2), headers=hdr,
                      json={"on": False, "reason": "the order was discharged"})
    assert lifted.status_code == 200
    detail = conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'LEGAL_HOLD_LIFTED'""", (v2,)).fetchone()[0]
    assert detail["prior_reason"] == "court order 2026-55"
    assert detail["prior_placed_by"] == str(uid)


def test_a_document_above_the_caller_or_on_a_source_above_it_is_404(conn, api):
    _uid, amber = _caller(conn, clearance="AMBER")
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    red_doc = _doc(conn, source, "post:red", classification="RED")
    red_source = h.source(conn, P, kind="RSS", parser="rss", due=False,
                           classification="RED")
    on_red = _doc(conn, red_source)
    body = {"on": True, "reason": "court order 9"}
    for doc in (red_doc, on_red, uuid4()):
        r = api.post(_url(doc), headers=amber, json=body)
        assert r.status_code == 404, doc


def test_a_version_above_the_caller_refuses_the_whole_hold(conn, api):
    _uid, amber = _caller(conn, clearance="AMBER")
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    v1 = _doc(conn, source, classification="RED")
    v2 = _doc(conn, source, version=2, supersedes=v1)
    r = api.post(_url(v2), headers=amber, json={"on": True, "reason": "court order 9"})
    assert r.status_code == 409
    assert conn.execute("SELECT bool_or(legal_hold) FROM collect.document "
                        "WHERE source_id = %s", (source,)).fetchone()[0] is False


def test_an_administrator_with_no_content_permission_cannot_hold(conn, api):
    _uid, admin = _caller(conn, roles=("SYS_ADMIN",))
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    doc = _doc(conn, source)
    for on in (True, False):
        r = api.post(_url(doc), headers=admin, json={"on": on, "reason": "court order"})
        assert r.status_code == 403


def test_the_database_refuses_a_hold_with_no_reason(conn):
    import psycopg

    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    doc = _doc(conn, source)
    with pytest.raises(psycopg.errors.CheckViolation, match="document_hold_has_reason"):
        conn.execute("UPDATE collect.document SET legal_hold = true WHERE id = %s",
                     (doc,))


def test_the_listing_shows_the_hold_and_whether_the_caller_may_hold(conn, api):
    _uid, hdr = _caller(conn)
    _uid, analyst = _caller(conn, roles=("ANALYST",))
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    doc = _doc(conn, source)
    api.post(_url(doc), headers=hdr, json={"on": True, "reason": "court order 12"})
    body = api.get(f"/api/v1/collection/documents?source_id={source}",
                   headers=hdr).json()
    row = next(d for d in body["documents"] if d["id"] == str(doc))
    assert row["legal_hold"] is True and row["legal_hold_reason"] == "court order 12"
    assert body["can_hold"] is True
    theirs = api.get(f"/api/v1/collection/documents?source_id={source}",
                     headers=analyst).json()
    assert theirs["can_hold"] is False
    # The free-text reason can name the matter the hold serves: a reader
    # who neither places nor lifts holds sees that there is one, not why
    # (2026-09-25).
    seen = next(d for d in theirs["documents"] if d["id"] == str(doc))
    assert seen["legal_hold"] is True and seen["legal_hold_reason"] is None


def test_a_held_document_stays_out_of_the_purge(conn, api):
    from noctornal_api.retention import RetentionService

    uid, hdr = _caller(conn)
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    doc = _doc(conn, source)
    api.post(_url(doc), headers=hdr, json={"on": True, "reason": "court order 13"})
    RetentionService(conn).purge_due(actor_id=uid, authority="retention schedule",
                                     dry_run=False)
    assert conn.execute("SELECT purged_at FROM collect.document WHERE id = %s",
                        (doc,)).fetchone()[0] is None
