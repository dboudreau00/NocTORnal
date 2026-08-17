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
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from test_collection_pg import _case, _source, _user  # noqa: E402


@pytest.fixture
def conn():
    """Its own connection and teardown, matching `test_collection_pg`'s.

    The helpers are imported from that module but the FIXTURE is not --
    a pytest fixture is not importable, and depending on one defined in
    another test module would bind these tests to that file's collection
    order. Teardown follows the foreign keys, not the reading order:
    hits before documents, documents before sources, assignments before
    cases.
    """
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test')"
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
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test'")
    c.close()


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
           VALUES (%s, %s, '{"keywords":["ransom"]}'::jsonb, %s, %s, %s)
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
    assert hits[0]["matched_on"] == {"keywords": ["ransom"]}
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
