"""Phase 4's read path: what the collector collected, readable by a human.

## Why this file exists

`collect.document` and `collect.watch_hit` were written by the collector
from the day Phase 4 landed and read by NOTHING. No endpoint, no UI, no
search reach -- `SearchService` covers `core.node` and `core.evidence`
only, and `document.search_tsv`'s GIN index was used by no query in the
tree. The only observable trace of a poll was three integers on a run
card. A watch could fire four hundred times and an analyst saw the number
400 and could not open one of them.

That is the tags/node-sets defect one layer up: not a service with no
caller, an entire phase with no caller. `collection.py` is 1,236 lines
with SSRF hardening, XXE refusal, an envelope-encrypted persona vault and
PARTIAL run status for dead watch patterns -- all of it landing in two
tables nobody could open.

The lifecycle columns show the intent was never finished rather than
decided against: `notified_at`, `suppressed`, `acknowledged_by`,
`acknowledged_at` and a partial index for the unnotified set, none of them
written or read by anything before this.

## The second half (2026-09-02)

The read path made `suppressed`, `suppress_reason` and `triage_state`
VISIBLE and left them unwritable. The Collected pane said "suppressed hits
are shown with their reason" and offered a triage filter over
NEW/TRIAGED/LINKED/DISCARDED, and no production path ever set any of
them: `_match_watches` drops a suppressed match before the row is written
(so `suppressed = true` was never stored), and nothing touched
`triage_state` after the INSERT default. The UI was describing rows that
could only be created by a test. `suppress_hit`, `unsuppress_hit` and
`set_document_triage` are the writers, and the tests at the bottom of
this file read both sides -- service and router -- so the pane's claim is
finally true of something.

`notified_at` is still written by nothing, deliberately: there is no
notification kind for a watch hit, and inventing one here would be a
registry decision that belongs with the notifications work, not with
this.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from test_collection_pg import _case, _source, _user  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated"
)

PASSWORD = "correct-horse-battery-staple"

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    """Its own connection and teardown, matching `test_collection_pg`'s.

    The helpers are imported from that module but the FIXTURE is not --
    a pytest fixture is not importable, and depending on one defined in
    another test module would bind these tests to that file's collection
    order. Teardown follows the foreign keys, not the reading order:
    hits before documents, documents before sources, assignments before
    cases.

    Two email prefixes. `col-` is shared with `test_collection_pg` (the
    imported `_user` helper mints it); `colh-` is this file's own, for
    the users the HTTP tests log in as. Those carry sessions and global
    roles that `test_collection_pg`'s teardown does not know to delete
    first, and `LIKE 'col-%'` does not match `colh-` (the hyphen is
    literal), so the two sweeps cannot trip over each other.
    """
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = ("(SELECT id FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test'"
           " OR email LIKE 'colh-%@noctornal.test')")
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'test-src-%')"
    with c.transaction():
        c.execute(f"DELETE FROM collect.watch_hit WHERE watch_id IN "
                  f"(SELECT id FROM collect.watch WHERE source_id IN {ssub})")
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.watch WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_account WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test'"
                  " OR email LIKE 'colh-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # A limiter this test owns: Redis is shared and blind to test
    # boundaries, so one test's budget would be another test's flake.
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _http_user(conn, *, clearance="RED", roles=("CASE_OWNER",)):
    """A user that can log in: TOTP enrolled, global roles granted. The
    default CASE_OWNER holds global `collection.read` (0039), which is
    what the document triage route is gated on."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"colh-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Collector", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _doc(conn, source_id, *, title="A thread", body="body text",
         classification="AMBER", triage="NEW", posted=None, handle="vendor01"):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, external_url, title, body_text,
                author_handle, posted_at, content_sha256, classification,
                triage_state)
           VALUES (%s, %s, 'https://forum.test/t/1', %s, %s, %s, %s,
                   decode(md5(%s), 'hex'), %s::core.tlp, %s)
           RETURNING id""",
        (source_id, uuid4().hex, title, body, handle,
         posted or datetime.now(timezone.utc), body, classification, triage),
    ).fetchone()[0]


def _watch(conn, source_id, case_id, owner, name="watch-1"):
    return conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref,
                keywords, owner_user_id)
           VALUES (%s, %s, %s, 'BOARD', 'https://forum.test/b/1',
                   ARRAY['ransom'], %s)
           RETURNING id""",
        (case_id, source_id, name, owner)).fetchone()[0]


def _hit(conn, watch_id, document_id, *, score=0.5, suppressed=False,
         reason=None):
    return conn.execute(
        """INSERT INTO collect.watch_hit
               (watch_id, document_id, matched_on, score, suppressed,
                suppress_reason)
           VALUES (%s, %s, '["selector:ransom"]'::jsonb, %s, %s, %s)
           RETURNING id""",
        (watch_id, document_id, score, suppressed, reason)).fetchone()[0]


# --- documents ----------------------------------------------------------

def test_a_collected_document_can_be_read_back(conn):
    from noctornal_api.collection import CollectionService

    src = _source(conn)
    _doc(conn, src, title="Ransomware crew recruiting")
    docs = CollectionService(conn).documents(clearance="RED")
    mine = [d for d in docs if d["title"] == "Ransomware crew recruiting"]
    assert mine, "a collected document is not reachable by any read method"
    assert mine[0]["source_name"].startswith("test-src-")
    assert mine[0]["excerpt"]


def test_a_document_above_the_callers_clearance_is_not_returned(conn):
    """`collect.document.classification` defaults to AMBER and can be
    higher. The existing collection endpoints do no classification
    filtering at all, so this had to not copy them."""
    from noctornal_api.collection import CollectionService

    src = _source(conn)
    _doc(conn, src, title="Red thread", classification="RED")
    svc = CollectionService(conn)
    assert not [d for d in svc.documents(clearance="AMBER")
                if d["title"] == "Red thread"]
    assert [d for d in svc.documents(clearance="RED")
            if d["title"] == "Red thread"]


def test_a_purged_document_is_omitted_not_returned_empty(conn):
    """`retention` NULLs `body_text` and stamps `purged_at`. Returning the
    row would render a destroyed exhibit as an empty document -- a
    deletion reported as a blank, which is this codebase's recurring
    shape."""
    from noctornal_api.collection import CollectionService

    src = _source(conn)
    doc = _doc(conn, src, title="Purged thread")
    conn.execute("UPDATE collect.document SET purged_at = now(), "
                 "body_text = '' WHERE id = %s", (doc,))
    assert not [d for d in CollectionService(conn).documents(clearance="RED")
                if d["title"] == "Purged thread"]


def test_a_long_body_is_excerpted_and_says_so(conn):
    """A list endpoint that returns every body pulls megabytes to render
    twenty titles. `truncated` is what stops the excerpt being mistaken
    for the whole post."""
    from noctornal_api.collection import CollectionService

    src = _source(conn)
    _doc(conn, src, title="Long", body="x" * 900)
    d = [x for x in CollectionService(conn).documents(clearance="RED")
         if x["title"] == "Long"][0]
    assert len(d["excerpt"]) == 400
    assert d["truncated"] and d["body_length"] == 900


def test_documents_can_be_filtered_by_triage_state(conn):
    """`document.triage_state` has had a supporting partial index since
    0011 and zero references in the service tree."""
    from noctornal_api.collection import CollectionService

    src = _source(conn)
    _doc(conn, src, title="New one", triage="NEW")
    _doc(conn, src, title="Done one", triage="DISCARDED")
    titles = [d["title"] for d in CollectionService(conn).documents(
        clearance="RED", source_id=src, triage_state="DISCARDED")]
    assert titles == ["Done one"]


# --- watch hits ---------------------------------------------------------

def test_a_watch_hit_can_be_opened(conn):
    """The whole point. Before this, a watch firing was an integer."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    doc = _doc(conn, src, title="Ransom thread")
    watch = _watch(conn, src, case, owner)
    _hit(conn, watch, doc, score=0.9)

    hits = CollectionService(conn).watch_hits(case, clearance="RED")
    assert len(hits) == 1
    assert hits[0]["title"] == "Ransom thread"
    assert hits[0]["watch_name"] == "watch-1"
    # A LIST, because that is what the collector writes (collection.py
    # `matched.append(f"regex:{pattern}")`, asserted by test_collection_pg).
    # This fixture fabricated a dict for three weeks, the UI rendered
    # Object.keys() of whatever arrived, and both were green while every
    # real hit on screen said it fired on "0, 1".
    assert hits[0]["matched_on"] == ["selector:ransom"]
    assert hits[0]["external_url"]


def test_a_suppressed_hit_is_shown_with_its_reason(conn):
    """Alert hygiene is not the same as nothing happening. Hiding
    suppressed hits makes a watch that is drowning in one recurring thread
    look like a watch that is quiet, and those need opposite responses."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    doc = _doc(conn, src)
    watch = _watch(conn, src, case, owner)
    _hit(conn, watch, doc, suppressed=True, reason="same thread within 1h")

    hit = CollectionService(conn).watch_hits(case, clearance="RED")[0]
    assert hit["suppressed"] is True
    assert hit["suppress_reason"] == "same thread within 1h"


def test_unacknowledged_hits_sort_first(conn):
    """Inverted priority: a hit nobody has looked at outranks a
    higher-scoring one somebody has already dealt with."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    high = _hit(conn, _watch(conn, src, case, owner, "w-high"),
                _doc(conn, src, title="High score"), score=0.99)
    _hit(conn, _watch(conn, src, case, owner, "w-low"),
         _doc(conn, src, title="Low score"), score=0.10)
    svc = CollectionService(conn)
    svc.acknowledge_hit(high, user_id=owner, clearance="RED")

    titles = [h["title"] for h in svc.watch_hits(case, clearance="RED")]
    assert titles[0] == "Low score", (
        "an acknowledged high-scoring hit outranked an unread one")


def test_acknowledging_is_idempotent_and_does_not_restamp(conn):
    """`acknowledged_at` is the only evidence of how long a hit sat
    unread. Re-acknowledging must not rewrite when somebody first saw
    it."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner), _doc(conn, src))
    svc = CollectionService(conn)
    first = svc.acknowledge_hit(hit, user_id=owner, clearance="RED")
    second = svc.acknowledge_hit(hit, user_id=owner, clearance="RED")
    assert first["acknowledged_at"] == second["acknowledged_at"]
    assert first["acknowledged_by"] == second["acknowledged_by"]


def test_a_hit_above_the_callers_clearance_cannot_be_acknowledged(conn):
    """Not merely hidden from the list. The clearance predicate is inside
    the UPDATE so there is no window between deciding and writing."""
    from noctornal_api.collection import CollectionError, CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner),
               _doc(conn, src, classification="RED"))
    with pytest.raises(CollectionError):
        CollectionService(conn).acknowledge_hit(
            hit, user_id=owner, clearance="AMBER")


def test_watch_hits_do_not_leak_across_cases(conn):
    """`collect.watch` carries the case; the document it matched does
    not."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    mine, theirs = _case(conn, owner), _case(conn, owner)
    src = _source(conn)
    _hit(conn, _watch(conn, src, theirs, owner), _doc(conn, src))
    assert CollectionService(conn).watch_hits(mine, clearance="RED") == []


# --- suppression: the writer the pane was describing ---------------------

def _audit_rows(conn, action, object_id):
    return conn.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = %s AND object_id = %s", (action, object_id)).fetchall()


def test_suppressing_a_hit_lists_it_with_its_reason(conn):
    """Before this, the only way a hit could list as suppressed was a test
    inserting the row that way. Now an analyst can say "this thread is
    noise" and the list shows the chip AND the reason, and the audit log
    shows who said so."""
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner), _doc(conn, src))
    svc = CollectionService(conn)

    out = svc.suppress_hit(case, hit, actor_id=owner,
                           reason="same thread reposted hourly", clearance="RED")
    assert out["suppressed"] is True
    listed = svc.watch_hits(case, clearance="RED")[0]
    assert listed["suppressed"] is True
    assert listed["suppress_reason"] == "same thread reposted hourly"
    rows = _audit_rows(conn, "WATCH_HIT_SUPPRESSED", hit)
    assert rows and rows[0][0] == owner
    assert rows[0][1]["reason"] == "same thread reposted hourly"


def test_a_suppress_reason_shorter_than_five_characters_is_refused(conn):
    """A suppression with no usable reason is a hit that vanished from the
    queue for no stated cause -- which is the shape the pane exists to
    prevent. Same floor as a persona status change."""
    from noctornal_api.collection import CollectionError, CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner), _doc(conn, src))
    svc = CollectionService(conn)
    with pytest.raises(CollectionError):
        svc.suppress_hit(case, hit, actor_id=owner, reason="dup", clearance="RED")
    with pytest.raises(CollectionError):
        svc.suppress_hit(case, hit, actor_id=owner, reason="    ", clearance="RED")
    assert svc.watch_hits(case, clearance="RED")[0]["suppressed"] is False


def test_unsuppressing_clears_the_reason_and_is_audited(conn):
    from noctornal_api.collection import CollectionService

    owner = _user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner), _doc(conn, src))
    svc = CollectionService(conn)
    svc.suppress_hit(case, hit, actor_id=owner, reason="same thread again",
                     clearance="RED")
    svc.unsuppress_hit(case, hit, actor_id=owner, clearance="RED")
    listed = svc.watch_hits(case, clearance="RED")[0]
    assert listed["suppressed"] is False
    assert listed["suppress_reason"] is None
    assert _audit_rows(conn, "WATCH_HIT_UNSUPPRESSED", hit)


def test_a_hit_cannot_be_suppressed_through_another_case_or_above_clearance(conn):
    """Two refusals with the same shape as `acknowledge_hit`: the case in
    the path must be the case the watch belongs to (the route gate
    authorised against THAT case, not the hit's), and a hit on a document
    above the caller's clearance is not merely hidden but unwritable."""
    from noctornal_api.collection import CollectionNotFound, CollectionService

    owner = _user(conn)
    mine, theirs = _case(conn, owner), _case(conn, owner)
    src = _source(conn)
    foreign = _hit(conn, _watch(conn, src, theirs, owner), _doc(conn, src))
    red = _hit(conn, _watch(conn, src, mine, owner),
               _doc(conn, src, classification="RED"))
    svc = CollectionService(conn)
    with pytest.raises(CollectionNotFound):
        svc.suppress_hit(mine, foreign, actor_id=owner,
                         reason="not mine to silence", clearance="RED")
    with pytest.raises(CollectionNotFound):
        svc.suppress_hit(mine, red, actor_id=owner,
                         reason="above my clearance", clearance="AMBER")
    assert not conn.execute(
        "SELECT 1 FROM collect.watch_hit WHERE id IN (%s, %s) AND suppressed",
        (foreign, red)).fetchone()


def test_suppress_over_http_goes_through_the_case_gate_and_the_service(conn, client):
    """Both halves. The router's job is to take the case from the PATH
    and the caller's own ceiling, and hand both to the service; a short
    reason is a 400 carrying the service's words, not a 422 from a
    validator that duplicates the rule."""
    owner, email, secret = _http_user(conn)
    case = _case(conn, owner)
    src = _source(conn)
    hit = _hit(conn, _watch(conn, src, case, owner), _doc(conn, src))
    hdr = _auth(_login(client, email, secret))
    base = f"/api/v1/cases/{case}/collection/watch-hits/{hit}"

    r = client.post(f"{base}/suppress", headers=hdr, json={"reason": "dup"})
    assert r.status_code == 400, r.text

    r = client.post(f"{base}/suppress", headers=hdr,
                    json={"reason": "same thread reposted hourly"})
    assert r.status_code == 200, r.text
    r = client.get(f"/api/v1/cases/{case}/collection/watch-hits", headers=hdr)
    assert r.status_code == 200, r.text
    listed = r.json()["hits"][0]
    assert listed["suppressed"] is True
    assert listed["suppress_reason"] == "same thread reposted hourly"

    r = client.post(f"{base}/unsuppress", headers=hdr)
    assert r.status_code == 200, r.text
    r = client.get(f"/api/v1/cases/{case}/collection/watch-hits", headers=hdr)
    assert r.json()["hits"][0]["suppressed"] is False


# --- triage: the dropdown finally has something to select -----------------

def test_triage_to_a_valid_state_persists_and_is_audited(conn):
    """`triage_state` has had a partial index since 0011 and a filter in
    `documents()` since the read path, and nothing ever moved a row off
    NEW. The states are 0011's own: NEW, TRIAGED, LINKED, DISCARDED."""
    from noctornal_api.collection import TRIAGE_STATES, CollectionService

    assert TRIAGE_STATES == ("NEW", "TRIAGED", "LINKED", "DISCARDED")
    owner = _user(conn)
    src = _source(conn)
    doc = _doc(conn, src, title="Needs a look")
    svc = CollectionService(conn)

    out = svc.set_document_triage(doc, "TRIAGED", actor_id=owner, clearance="RED")
    assert out["triage_state"] == "TRIAGED" and out["previous_state"] == "NEW"
    titles = [d["title"] for d in svc.documents(
        clearance="RED", source_id=src, triage_state="TRIAGED")]
    assert titles == ["Needs a look"]
    rows = _audit_rows(conn, "DOCUMENT_TRIAGED", doc)
    assert rows and rows[0][1] == {"from": "NEW", "to": "TRIAGED"}


def test_an_invalid_triage_state_is_refused_and_is_a_400_over_http(conn, client):
    """The dropdown's four values and the service's four values are the
    same list, and a fifth is refused rather than stored: a state the
    filter cannot select is a document that has disappeared from every
    view without being deleted."""
    from noctornal_api.collection import CollectionError, CollectionService

    owner, email, secret = _http_user(conn)
    src = _source(conn)
    doc = _doc(conn, src)
    with pytest.raises(CollectionError):
        CollectionService(conn).set_document_triage(
            doc, "ARCHIVED", actor_id=owner, clearance="RED")

    hdr = _auth(_login(client, email, secret))
    r = client.post(f"/api/v1/collection/documents/{doc}/triage", headers=hdr,
                    json={"state": "ARCHIVED"})
    assert r.status_code == 400, r.text
    r = client.post(f"/api/v1/collection/documents/{doc}/triage", headers=hdr,
                    json={"state": "DISCARDED"})
    assert r.status_code == 200, r.text
    assert r.json()["triage_state"] == "DISCARDED"
    r = client.get("/api/v1/collection/documents?triage_state=DISCARDED",
                   headers=hdr)
    assert str(doc) in {d["id"] for d in r.json()["documents"]}


def test_a_caller_below_the_documents_classification_cannot_triage_it(conn):
    """Not merely hidden from the list: the clearance predicate is inside
    the UPDATE, as it is for acknowledging a hit."""
    from noctornal_api.collection import CollectionNotFound, CollectionService

    owner = _user(conn)
    src = _source(conn)
    doc = _doc(conn, src, classification="RED")
    with pytest.raises(CollectionNotFound):
        CollectionService(conn).set_document_triage(
            doc, "DISCARDED", actor_id=owner, clearance="AMBER")
    state = conn.execute("SELECT triage_state FROM collect.document WHERE id = %s",
                         (doc,)).fetchone()[0]
    assert state == "NEW"
