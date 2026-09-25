"""Retention and legal hold for collected documents (2026-09-24; docs/00
decision 74).

The collector writes a document's retention clock from its category's rule,
which arms the purge's document leg for the first time. These hold that
decision to the code: a hold on any version of the document, a case
under legal hold citing any version through every registered citation,
and an unretracted assertion each keep it; the purge rechecks under
locks, so a hold or a citation made while it runs wins; raw markup and
identities go with the content; and the catalogue of references onto a
document, a run or a source fails on anything unregistered.
DATABASE_URL-gated.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-cdrt-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"""DELETE FROM core.tag_assignment WHERE tag_id IN
                        (SELECT id FROM core.tag WHERE case_id IN {csub})""")
        c.execute(f"DELETE FROM core.tag WHERE case_id IN {csub}")
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def owner(conn):
    uid, _ = h.user(conn, P, roles=("CASE_OWNER",))
    return uid


def _case(conn, owner, *, hold=False):
    from noctornal_api.cases import CaseService

    case = CaseService(conn).create(
        code=f"OP-CDRT-{uuid4().hex[:6]}", title="document retention",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)
    if hold:
        _hold_case(conn, case, True)
    return case


def _hold_case(conn, case, on):
    conn.execute('UPDATE core."case" SET legal_hold = %s, legal_hold_reason = %s '
                 'WHERE id = %s', (on, "court order 2026-77" if on else None, case))


def _source(conn):
    return h.source(conn, P, kind="RSS", parser="rss", due=False)


def _doc(conn, source, external_id="post:1", *, version=1, supersedes=None,
         past=True, key=None, run=None, watch=None, body="personal body"):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                supersedes_id, retain_until, body_html_key, title,
                external_url, author_handle, author_uid, collection_run_id,
                watch_id, category)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'a title',
                   'https://board.example.test/t/1', 'vendor_x', 'u:99', %s,
                   %s, 'CHAT_EXPORT')
           RETURNING id""",
        (source, external_id, body, os.urandom(32), version, supersedes,
         datetime.now(timezone.utc) - timedelta(days=1) if past else
         datetime.now(timezone.utc) + timedelta(days=30), key, run,
         watch)).fetchone()[0]


def _purge(conn, owner, store=None):
    from noctornal_api.retention import RetentionService

    return RetentionService(conn, document_raw=store).purge_due(
        actor_id=owner, authority="retention schedule", dry_run=False)


def _purged(conn, doc):
    return conn.execute("SELECT purged_at IS NOT NULL FROM collect.document "
                        "WHERE id = %s", (doc,)).fetchone()[0]


def _node_and_assertion(conn, case, owner, doc, *, retracted=False):
    node = uuid4()
    with conn.transaction():
        conn.execute("""INSERT INTO core.node (id, case_id, node_type, label, created_by)
                        VALUES (%s, %s, 'IDENTITY', %s, %s)""",
                     (node, case, f"cdrt-{node.hex[:6]}", owner))
        conn.execute("""INSERT INTO core.assertion
                            (case_id, node_id, basis, created_by, document_id,
                             retracted_at)
                        VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s, %s)""",
                     (case, node, owner, doc,
                      datetime.now(timezone.utc) if retracted else None))


def _cite(conn, how, case, owner, doc, source):
    """One of the registered citations of `doc` by `case`."""
    if how == "assertion":
        _node_and_assertion(conn, case, owner, doc, retracted=True)
    elif how == "proposal":
        conn.execute("""INSERT INTO collect.proposal
                            (case_id, kind, payload, origin, rationale, document_id)
                        VALUES (%s, 'NODE', '{}', 'cd', 'a reason', %s)""",
                     (case, doc))
    elif how == "contact_block":
        conn.execute(
            """INSERT INTO comms.contact_block
                   (case_id, source_ref, raw_text, raw_sha256, block_fingerprint,
                    parser_version, created_by, document_id)
               VALUES (%s, 'ref', 'jabber: x@y', %s, %s, 'v1', %s, %s)""",
            (case, os.urandom(32), uuid4().hex, owner, doc))
    elif how == "tag":
        tag = conn.execute("""INSERT INTO core.tag (namespace, name, case_id)
                              VALUES ('cd', %s, %s) RETURNING id""",
                           (uuid4().hex[:8], case)).fetchone()[0]
        conn.execute("""INSERT INTO core.tag_assignment (tag_id, assigned_by, document_id)
                        VALUES (%s, %s, %s)""", (tag, owner, doc))
    elif how == "watch_hit":
        watch = _watch(conn, case, source, owner)
        conn.execute("""INSERT INTO collect.watch_hit (watch_id, document_id, matched_on)
                        VALUES (%s, %s, '["keyword:x"]')""", (watch, doc))
    else:
        raise AssertionError(how)


def _watch(conn, case, source, owner):
    return conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
                                      target_ref, owner_user_id)
           VALUES (%s, %s, 'cdrt', 'FORUM', 'b', %s) RETURNING id""",
        (case, source, owner)).fetchone()[0]


# --- the clock ----------------------------------------------------------

def test_the_clock_comes_from_the_category_rule_and_a_missing_rule_is_a_note(conn):
    from noctornal_api.collection import CollectionService, FetchResult, Item

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    stub = h.StubAuthorityAdapter(retention_clock=True,
                                  default_category="CHAT_EXPORT")
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    h.authority(conn, recorder=recorder, confirmer=confirmer,
                source_ids=[source], adapters=h.adapters(stub))
    stub.produce = lambda ctx: FetchResult(items=[
        Item(external_id="post:1", body="clocked"),
        Item(external_id="post:2", body="unruled", category="MARKET_LISTING")])
    result = CollectionService(conn, h.adapters(stub)).run_once(source,
                                                                actor_id=None)
    rows = dict(conn.execute(
        """SELECT external_id, retain_until - captured_at FROM collect.document
            WHERE source_id = %s""", (source,)).fetchall())
    days = conn.execute("SELECT retain_days FROM core.retention_rule "
                        "WHERE category = 'CHAT_EXPORT'").fetchone()[0]
    assert rows["post:1"] == timedelta(days=days)
    assert rows["post:2"] is None
    assert any("No retention rule covers MARKET_LISTING" in n for n in result.notes)
    assert result.status == "OK", "an unclocked document is a note, not a fault"


# --- holds --------------------------------------------------------------

def test_a_clocked_document_under_its_own_hold_is_not_purged(conn, owner):
    source = _source(conn)
    doc = _doc(conn, source)
    conn.execute("""UPDATE collect.document SET legal_hold = true,
                           legal_hold_reason = 'court order 7' WHERE id = %s""", (doc,))
    result = _purge(conn, owner)
    assert not _purged(conn, doc) and result.held_back >= 1


@pytest.mark.parametrize("how", ["assertion", "proposal", "contact_block", "tag",
                                 "watch_hit", "collected_under_watch", "evidence_run"])
def test_a_document_cited_by_a_held_case_is_not_purged(conn, owner, how):
    source = _source(conn)
    case = _case(conn, owner, hold=True)
    if how == "collected_under_watch":
        doc = _doc(conn, source, watch=_watch(conn, case, source, owner))
    elif how == "evidence_run":
        run = conn.execute("INSERT INTO collect.collection_run (source_id, status) "
                           "VALUES (%s, 'OK') RETURNING id", (source,)).fetchone()[0]
        doc = _doc(conn, source, run=run)
        conn.execute(
            """INSERT INTO core.evidence
                   (case_id, title, media_type, byte_size, sha256, blake3,
                    storage_key, storage_bucket, acquired_by, acquired_at,
                    acquisition_method, classification, collection_run_id)
               VALUES (%s, 'cdrt', 'text/plain', 10, %s, %s, %s, 'b', %s, now(),
                       'MANUAL_UPLOAD', 'AMBER', %s)""",
            (case, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}", owner, run))
    else:
        doc = _doc(conn, source)
        _cite(conn, how, case, owner, doc, source)
    _purge(conn, owner)
    assert not _purged(conn, doc), how


def test_the_same_documents_are_purged_once_the_case_hold_is_lifted(conn, owner):
    source = _source(conn)
    case = _case(conn, owner, hold=True)
    doc = _doc(conn, source)
    _cite(conn, "proposal", case, owner, doc, source)
    _purge(conn, owner)
    assert not _purged(conn, doc)
    _hold_case(conn, case, False)
    _purge(conn, owner)
    assert _purged(conn, doc)


def test_an_earlier_version_of_a_cited_post_is_held_too(conn, owner):
    source = _source(conn)
    case = _case(conn, owner, hold=True)
    v1 = _doc(conn, source, "post:5")
    v2 = _doc(conn, source, "post:5", version=2, supersedes=v1, past=False)
    _cite(conn, "proposal", case, owner, v2, source)
    _purge(conn, owner)
    assert not _purged(conn, v1), "a court naming a post names its history"


def test_a_document_supporting_an_unretracted_assertion_is_pinned_and_a_retracted_one_is_not(conn, owner):
    source = _source(conn)
    case = _case(conn, owner)
    pinned = _doc(conn, source, "post:1")
    free = _doc(conn, source, "post:2")
    _node_and_assertion(conn, case, owner, pinned)
    _node_and_assertion(conn, case, owner, free, retracted=True)
    _purge(conn, owner)
    assert not _purged(conn, pinned) and _purged(conn, free)


def test_the_hold_reason_never_names_the_case(conn, owner):
    from noctornal_api.retention import RetentionService

    source = _source(conn)
    case = _case(conn, owner, hold=True)
    doc = _doc(conn, source)
    _cite(conn, "proposal", case, owner, doc, source)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s', (case,)).fetchone()[0]
    item = next(i for i in RetentionService(conn).due() if i.object_id == doc)
    assert item.held and item.hold_reason == "cited by a case under legal hold"
    assert code not in item.hold_reason and str(case) not in item.hold_reason


def test_held_documents_do_not_starve_the_sweep(conn, owner):
    from noctornal_api.retention import RetentionService

    source = _source(conn)
    held = [_doc(conn, source, f"post:{n}") for n in range(3)]
    for doc in held:
        conn.execute("""UPDATE collect.document SET legal_hold = true,
                               legal_hold_reason = 'hold' WHERE id = %s""", (doc,))
    unheld = _doc(conn, source, "post:9")
    items = [i for i in RetentionService(conn).due(limit=2)
             if i.object_type == "document"]
    assert items[0].object_id == unheld or not items[0].held


def test_more_than_500_held_documents_do_not_starve_one_purgeable_one(conn, owner):
    source = _source(conn)
    conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, retain_until,
                legal_hold, legal_hold_reason)
           SELECT %s, 'held:' || g, 'b', sha256(convert_to('cdrt' || g || %s, 'UTF8')),
                  now() - interval '1 day', true, 'hold'
             FROM generate_series(1, 501) g""", (source, uuid4().hex))
    unheld = _doc(conn, source, "post:free")
    result = _purge(conn, owner)
    assert _purged(conn, unheld)
    assert result.held_back >= 501, "the held count is its own query, not the list's"


def _in_thread(fn):
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def test_a_hold_placed_while_the_purge_runs_wins(conn, owner):
    from noctornal_api.db import connect

    source = _source(conn)
    case = _case(conn, owner)
    doc = _doc(conn, source)
    _cite(conn, "proposal", case, owner, doc, source)
    other = connect()
    purger = connect()
    try:
        other.autocommit = False
        other.execute('UPDATE core."case" SET legal_hold = true, '
                      "legal_hold_reason = 'court order' WHERE id = %s", (case,))
        thread, box = _in_thread(lambda: _purge(purger, owner))
        time.sleep(1.0)
        assert thread.is_alive(), "the purge waits on the citing case's lock"
        other.commit()
        thread.join(timeout=30)
        assert "error" not in box, box.get("error")
    finally:
        other.close()
        purger.close()
    assert not _purged(conn, doc)
    assert any("came under a legal hold between the sweep and the purge" in w
               for w in box["value"].warnings)


def test_a_citation_of_another_version_made_during_the_purge_waits_and_wins(conn, owner):
    from noctornal_api.db import connect

    source = _source(conn)
    case = _case(conn, owner)
    v1 = _doc(conn, source, "post:7")
    v2 = _doc(conn, source, "post:7", version=2, supersedes=v1, past=False)
    other = connect()
    purger = connect()
    try:
        other.autocommit = False
        node = uuid4()
        other.execute("""INSERT INTO core.node (id, case_id, node_type, label, created_by)
                         VALUES (%s, %s, 'IDENTITY', %s, %s)""",
                      (node, case, f"cdrt-{node.hex[:6]}", owner))
        other.execute("""INSERT INTO core.assertion (case_id, node_id, basis,
                                                     created_by, document_id)
                         VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s)""",
                      (case, node, owner, v2))
        thread, box = _in_thread(lambda: _purge(purger, owner))
        time.sleep(1.0)
        assert thread.is_alive(), "the purge waits for the citation's key-share lock"
        other.commit()
        thread.join(timeout=30)
        assert "error" not in box, box.get("error")
    finally:
        other.close()
        purger.close()
    assert not _purged(conn, v1), "the recheck saw the new pin on version 2"


# --- what the purge destroys and what it keeps -----------------------------

def test_the_purge_empties_content_and_identities_and_replaces_the_digest(conn, owner):
    source = _source(conn)
    doc = _doc(conn, source)
    conn.execute("""INSERT INTO collect.extraction (document_id, selector_type,
                        raw_value, norm_value, extractor)
                    SELECT %s, key, 'x@y.test', 'x@y.test', 'cd'
                      FROM core.selector_type LIMIT 1""", (doc,))
    before = conn.execute("SELECT content_sha256 FROM collect.document WHERE id = %s",
                          (doc,)).fetchone()[0]
    _purge(conn, owner)
    row = conn.execute(
        """SELECT body_text, title, external_url, author_handle, author_uid,
                  body_html_key, search_tsv, source_id, external_id,
                  category, content_sha256
             FROM collect.document WHERE id = %s""", (doc,)).fetchone()
    assert row[:7] == ("", None, None, None, None, None, None)
    assert row[7] == source and row[8] == "post:1" and row[9] == "CHAT_EXPORT"
    expected = hashlib.sha256(f"purged:{doc}".encode()).digest()
    assert bytes(row[10]) == expected and bytes(row[10]) != bytes(before)
    # The vectors live beside the document since 0094 (F6.1).
    assert conn.execute("SELECT count(*) FROM collect.document_embedding "
                        "WHERE document_id = %s", (doc,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM collect.extraction WHERE document_id = %s",
                        (doc,)).fetchone()[0] == 0, "the selectors go with the document"


def test_identity_matches_are_scrubbed_and_keyword_matches_kept(conn, owner):
    source = _source(conn)
    case = _case(conn, owner)
    watch = _watch(conn, case, source, owner)
    doc = _doc(conn, source)
    conn.execute("""INSERT INTO collect.watch_hit (watch_id, document_id, matched_on)
                    VALUES (%s, %s, '["keyword:selling", "author:u:99",
                                      "forwarded_from:c:-1005"]')""", (watch, doc))
    _purge(conn, owner)
    matched = conn.execute("SELECT matched_on FROM collect.watch_hit WHERE document_id = %s",
                           (doc,)).fetchone()[0]
    assert matched == ["keyword:selling", "author:[purged]", "forwarded_from:[purged]"]


def test_registered_side_table_scrubs_run_for_purged_documents(conn, owner, monkeypatch):
    from noctornal_api import retention

    conn.execute("CREATE TEMP TABLE cdrt_side (document_id uuid, handle text)")
    monkeypatch.setitem(retention.DOCUMENT_PURGE_SCRUBS, "pg_temp.cdrt_side.document_id",
                        "DELETE FROM cdrt_side WHERE document_id = ANY(%(ids)s)")
    source = _source(conn)
    doc = _doc(conn, source)
    kept = _doc(conn, source, "post:2", past=False)
    conn.execute("INSERT INTO cdrt_side VALUES (%s, 'a'), (%s, 'b')", (doc, kept))
    _purge(conn, owner)
    rows = [r[0] for r in conn.execute("SELECT document_id FROM cdrt_side").fetchall()]
    assert rows == [kept]


def test_raw_markup_goes_with_its_document_and_a_shared_object_stays(conn, owner):
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    store = InMemoryDocumentRawStorage()
    store.put("collect/aa/one", b"<p>one</p>")
    store.put("collect/bb/shared", b"<p>shared</p>")
    source = _source(conn)
    alone = _doc(conn, source, "post:1", key="collect/aa/one")
    shared = _doc(conn, source, "post:2", key="collect/bb/shared")
    _doc(conn, source, "post:3", key="collect/bb/shared", past=False)
    result = _purge(conn, owner, store)
    assert _purged(conn, alone) and _purged(conn, shared)
    assert not store.exists("collect/aa/one") and store.exists("collect/bb/shared")
    assert any("still used by other documents" in w for w in result.warnings)
    outcome = conn.execute(
        """SELECT storage_outcome, object_count FROM core.purge_tombstone
            WHERE object_type = 'document' ORDER BY purged_at DESC LIMIT 1""").fetchone()
    assert outcome[0] == "DELETED"


def test_a_failed_raw_delete_keeps_the_document_due_and_names_the_key(conn, owner):
    class Refusing:
        def delete(self, key):
            raise RuntimeError("the store is read only")

    source = _source(conn)
    doc = _doc(conn, source, key="collect/cc/refused")
    result = _purge(conn, owner, Refusing())
    assert not _purged(conn, doc)
    assert any("collect/cc/refused" in w for w in result.warnings)


def test_the_purge_refuses_without_a_raw_store_when_raw_markup_is_due(conn, owner):
    from noctornal_api.retention import RetentionError

    source = _source(conn)
    doc = _doc(conn, source, key="collect/dd/nostore")
    with pytest.raises(RetentionError, match="no store for collected raw markup"):
        _purge(conn, owner, None)
    assert not _purged(conn, doc)


def test_no_exhibit_bytes_are_deleted_before_the_raw_store_refusal(conn, owner, monkeypatch):
    """2026-09-25: the document leg's refusal came after
    the evidence leg had asked the object store to delete exhibit bytes in
    the same transaction, so its rollback would unmark rows whose bytes
    were gone. It is now said before the transaction starts."""
    from noctornal_api.retention import DueItem, RetentionError, RetentionService

    source = _source(conn)
    doc = _doc(conn, source, key="collect/ee/nostore")
    now = datetime.now(timezone.utc)
    exhibit = DueItem(object_type="evidence", object_id=uuid4(), case_id=None,
                      deadline=now, rule="case.retention_until")
    document = DueItem(object_type="document", object_id=doc, case_id=None,
                       deadline=now, rule="retention_rule")
    asked = []
    purger = RetentionService(conn, storage=object(), document_raw=None)
    monkeypatch.setattr(purger, "due", lambda **_kw: [exhibit, document])
    monkeypatch.setattr(purger, "_purge_evidence",
                        lambda ids: asked.append(ids))
    with pytest.raises(RetentionError, match="no store for collected raw markup"):
        purger.purge_due(actor_id=owner, authority="retention schedule",
                         dry_run=False)
    assert asked == [], "the exhibit store was never asked to delete anything"
    assert not _purged(conn, doc)


def test_a_hold_that_waited_on_the_purge_does_not_report_a_destroyed_document(conn, owner):
    """2026-09-25: a hold whose
    write waited on the purge's version locks used to go on to write, and
    answer, a hold on the row the purge had just destroyed. It now locks
    the versions first and reads the document after the wait: a destroyed
    document is the 404 a missing one is, and nothing is audited."""
    from noctornal_api.db import connect
    from noctornal_api.retention import RetentionNotFound, RetentionService

    source = _source(conn)
    case = _case(conn, owner)
    doc = _doc(conn, source)
    _cite(conn, "proposal", case, owner, doc, source)
    other, purger, holder = connect(), connect(), connect()
    try:
        # Holds the citing case, so the purge stops there with every
        # version of the document locked.
        other.autocommit = False
        other.execute('UPDATE core."case" SET title = title WHERE id = %s', (case,))
        purging, purged_box = _in_thread(lambda: _purge(purger, owner))
        time.sleep(1.0)
        assert purging.is_alive(), "the purge waits on the citing case"
        holding, held_box = _in_thread(
            lambda: RetentionService(holder).set_document_legal_hold(
                doc, actor_id=owner, on=True, reason="preservation order 9",
                clearance="RED"))
        time.sleep(1.0)
        assert holding.is_alive(), "the hold waits on the purge's version locks"
        other.commit()
        purging.join(timeout=30)
        holding.join(timeout=30)
        assert "error" not in purged_box, purged_box.get("error")
    finally:
        other.close()
        purger.close()
        holder.close()
    assert _purged(conn, doc)
    assert isinstance(held_box.get("error"), RetentionNotFound), held_box
    assert conn.execute("SELECT legal_hold FROM collect.document WHERE id = %s",
                        (doc,)).fetchone()[0] is False
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE object_id = %s AND action = 'LEGAL_HOLD_APPLIED'""",
        (doc,)).fetchone()[0] == 0


def test_the_tombstone_names_only_the_purged_ids_and_what_happened_to_markup(conn, owner):
    source = _source(conn)
    purged = _doc(conn, source, "post:1")
    held = _doc(conn, source, "post:2")
    conn.execute("""UPDATE collect.document SET legal_hold = true,
                           legal_hold_reason = 'hold' WHERE id = %s""", (held,))
    _purge(conn, owner)
    count, outcome = conn.execute(
        """SELECT object_count, storage_outcome FROM core.purge_tombstone
            WHERE object_type = 'document' ORDER BY purged_at DESC LIMIT 1""").fetchone()
    assert _purged(conn, purged) and not _purged(conn, held)
    assert outcome == "NOT_APPLICABLE" and count >= 1


def test_the_unclocked_warning_keeps_its_phrase_and_names_the_two_causes(conn, owner):
    from noctornal_api.retention import RetentionService

    source = _source(conn)
    conn.execute(
        """INSERT INTO collect.document (source_id, external_id, body_text,
                                         content_sha256)
           VALUES (%s, 'post:u', 'x', %s)""", (source, os.urandom(32)))
    result = RetentionService(conn).purge_due(actor_id=owner, authority="t",
                                              dry_run=True)
    warning = next(w for w in result.warnings if "no retention clock" in w)
    assert "RSS items" in warning and "no retention rule" in warning
    assert "—" not in warning and "(s)" not in warning


def test_a_case_scoped_sweep_still_never_touches_documents(conn, owner):
    from noctornal_api.retention import RetentionService

    source = _source(conn)
    _doc(conn, source)
    case = _case(conn, owner)
    assert not [i for i in RetentionService(conn).due(case_id=case)
                if i.object_type == "document"]


def test_a_refetch_after_purge_is_a_new_capture(conn, owner):
    from noctornal_api.collection import CollectionService, FetchResult, Item

    source = _source(conn)
    doc = _doc(conn, source, "t-1", body="d")

    class Rss:
        key, version = "rss", "t"

        def fetch(self, **kw):
            return FetchResult(items=[Item(external_id="t-1", title="a title",
                                           body="d")])

    _purge(conn, owner)
    assert _purged(conn, doc)
    result = CollectionService(conn, {"rss": Rss()}).run_once(source, actor_id=None)
    assert result.items_new == 1


# --- the catalogue ------------------------------------------------------

def _foreign_keys(conn, target):
    return conn.execute(
        """SELECT n.nspname || '.' || c.relname || '.' || a.attname,
                  EXISTS (SELECT 1 FROM information_schema.columns ic
                           WHERE ic.table_schema = n.nspname
                             AND ic.table_name = c.relname
                             AND ic.column_name = 'case_id')
             FROM pg_constraint k
             JOIN pg_class c ON c.oid = k.conrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
            WHERE k.contype = 'f' AND k.confrelid = %s::regclass""",
        (target,)).fetchall()


def _unclassified(conn) -> list[str]:
    from noctornal_api import retention

    known = ({key for key, _sql in retention.DOCUMENT_CITATIONS}
             | set(retention.DOCUMENT_REFERENCES_NOT_CASE_MATERIAL))
    bad = [fk for fk, _case in _foreign_keys(conn, "collect.document")
           if fk not in known]
    run_source = (set(retention.DOCUMENT_RUN_AND_SOURCE_CITATIONS)
                  | set(retention.RUN_AND_SOURCE_REFERENCES_NOT_CITATIONS))
    for target in ("collect.collection_run", "collect.source"):
        bad += [fk for fk, has_case in _foreign_keys(conn, target)
                if has_case and fk not in run_source]
    return bad


def test_every_reference_to_a_collected_document_is_classified(conn):
    from noctornal_api import retention

    assert _unclassified(conn) == []
    for key in retention.DOCUMENT_REFERENCES_NOT_CASE_MATERIAL:
        if key in retention._SCRUB_EXEMPT:
            continue
        assert key in retention.DOCUMENT_PURGE_SCRUBS, (
            f"{key} is a side table with no scrub: register one, or a reason "
            f"that it holds no personal data")


def test_the_catalogue_covers_run_and_source_citations(conn):
    from noctornal_api import retention

    for key, leg in retention.DOCUMENT_RUN_AND_SOURCE_CITATIONS.items():
        assert leg in retention._DOCUMENT_HELD_SQL, f"{key} is registered and not followed"
    with conn.transaction():
        conn.execute("""CREATE TABLE collect.cdrt_probe (
                            id uuid PRIMARY KEY, case_id uuid,
                            run_id uuid REFERENCES collect.collection_run(id))""")
        try:
            assert "collect.cdrt_probe.run_id" in _unclassified(conn)
        finally:
            conn.execute("DROP TABLE collect.cdrt_probe")


def test_the_hold_legs_use_their_document_indexes(conn):
    wanted = {"collect.proposal": "proposal_document_idx",
              "comms.contact_block": "contact_block_document_idx",
              "collect.watch_hit": "watch_hit_document_idx",
              "core.tag_assignment": "tag_assignment_document_idx"}
    with conn.transaction():
        conn.execute("SET LOCAL enable_seqscan = off")
        for table, index in wanted.items():
            plan = " ".join(r[0] for r in conn.execute(
                f"EXPLAIN SELECT 1 FROM {table} WHERE document_id = %s",
                (uuid4(),)).fetchall())
            assert index in plan, (table, plan)
